mod archiver;
mod codec;
mod container;
mod io_engine;
mod nl;
mod pool;
mod protocol;
mod resource;
mod scheduler;
mod worker;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use codec::{CodecId, Preset};
use container::ContainerFormat;
use protocol::{DEFAULT_MAX_FRAME_BYTES, SecurityMode, WireCodec};
use resource::{
    ClusterFileConfig, NodeSpec, auto_mem_limit_bytes, discover_default_cluster_config,
    interactive_pick, load_cluster_file, parse_size, probe_local_system, run_doctor,
    run_init_wizard,
};
use scheduler::{
    CompressParams, DecompressParams, PackParams, ScheduleMode, hash_file_blake3, hex_encode,
    probe_nodes, run_compress, run_decompress, run_inspect, run_net_bench, run_pack, run_unpack,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use worker::{WorkerConfig, run_worker};

#[derive(Parser)]
#[command(
    name = "crushgrid",
    version,
    about = "Distributed multi-node compression and archival CLI for LAN, VPN, and cloud hosts",
    after_help = "Presets (-m / --preset):\n  \
  fast      Maximum speed (Zstd L3)\n  \
  balanced  Everyday speed and ratio (Zstd L9 + LDM, default)\n  \
  small     High ratio, fast multi-codec (Bzip3 on text/CSV, LZMA2+BCJ on binaries, LZMA2 L6 on mixed)\n  \
  max       Smallest archive (Bzip3 16M on text/code, LZMA2+BCJ L9 on binaries, LZMA2 L9 on mixed)\n\n\
Quick Examples:\n  \
  crushgrid init                                      # Generate ~/.config/crushgrid/cluster.conf\n  \
  crushgrid doctor                                    # Inspect CPU, RAM, config, and TCP stack\n  \
  crushgrid pack ./data --preset small                # Zero-config archive (auto-discovers user config)\n  \
  crushgrid unpack data.sqz                           # Extract in parallel\n  \
  crushgrid do \"compress ./logs as small as possible\" # Natural-language command mode"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Shared cluster, transport, and resource-budget arguments (flattened across commands so every `-h` flag is documented).
#[derive(Args, Clone)]
struct ClusterArgs {
    /// Path to an N-node cluster config file (defaults to user/system config if present)
    #[arg(long)]
    cluster: Option<PathBuf>,

    /// Ignore any saved cluster.conf and run locally only (preserves --node local:... limits)
    #[arg(long, default_value_t = false)]
    local: bool,

    /// Node allocation spec (repeatable), e.g. local:threads=8,mem=2G or host:7878:threads=max,bw=10M
    #[arg(long = "node")]
    node: Vec<String>,

    /// Comma-separated shorthand list of nodes, e.g. local,192.168.1.40:7878
    #[arg(long)]
    nodes: Option<String>,

    /// Launch interactive CLI device and resource picker before starting
    #[arg(short = 'i', long, default_value_t = false)]
    pick: bool,

    /// Shared cluster auth token (recommended: set CRUSHGRID_TOKEN env var instead of CLI flag)
    #[arg(long, env = "CRUSHGRID_TOKEN", default_value = "")]
    token: String,

    /// Transport security mode: aead (AES-256-GCM, default) or auth-only (for WireGuard/Tailscale)
    #[arg(long)]
    security: Option<String>,

    /// Scheduler policy: auto (cost-aware, default), force-all, or local-only
    #[arg(long, default_value = "auto")]
    schedule: String,

    /// Wire pre-shrink codec: auto (zstd1 on <100 MiB/s links, lz4 on >=100 MiB/s), zstd1, lz4, none
    #[arg(long)]
    wire_codec: Option<String>,

    /// Coordinator hard RAM ceiling (defaults to 1/3 available RAM, clamped to 256M..4G)
    #[arg(long)]
    mem_limit: Option<String>,

    /// Parallel TCP streams per remote worker (1..=8, default 2)
    #[arg(long)]
    streams: Option<usize>,

    /// Disable tail speculative hedging for final remote slabs
    #[arg(long, default_value_t = false)]
    no_hedge: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Translate a natural-language request into a crushgrid command and run it
    #[command(name = "do", visible_alias = "ask")]
    Do {
        /// Natural-language request, e.g. "compress ./backups as small as possible using 50% cpu"
        #[arg(required = true, num_args = 1..)]
        request: Vec<String>,

        /// Print the resolved CLI command without executing it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Interactive or scriptable cluster setup wizard (generates a 256-bit CSPRNG token and 0600 cluster.conf)
    Init {
        /// Output config path (defaults to ~/.config/crushgrid/cluster.conf or %APPDATA%\crushgrid\cluster.conf)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Comma-separated remote worker addresses (non-interactive mode)
        #[arg(long)]
        nodes: Option<String>,

        /// Default security mode: aead (default) or auth-only
        #[arg(long, default_value = "aead")]
        security: String,

        /// Overwrite an existing cluster.conf file
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Inspect local CPU, RAM, auto-detected cluster.conf, built-in codecs, and OS TCP stack
    Doctor,

    /// Run a secure multi-stream compute worker daemon with hard CPU/RAM ceilings
    Worker {
        /// Listen address (e.g. 0.0.0.0:7878 or your Tailscale IP:7878)
        #[arg(long, default_value = "0.0.0.0:7878")]
        bind: SocketAddr,

        /// Shared authentication token (recommended: set CRUSHGRID_TOKEN env var instead of CLI flag)
        #[arg(long, env = "CRUSHGRID_TOKEN")]
        token: String,

        /// Hard ceiling on CPU threads this worker will ever allocate
        #[arg(long)]
        max_threads: Option<usize>,

        /// Hard ceiling on RAM buffers (e.g. 4G, 512M)
        #[arg(long, default_value = "4G")]
        max_mem: String,

        /// Allow auth-only (no wire encryption) sessions for WireGuard/Tailscale links
        #[arg(long, default_value_t = false)]
        allow_auth_only: bool,
    },

    /// Probe available nodes, CPU/RAM ceilings, RTT, and live link bandwidth
    Probe {
        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        /// Node spec (repeatable)
        #[arg(long = "node")]
        node: Vec<String>,

        /// Comma-separated shorthand list of nodes
        #[arg(long)]
        nodes: Option<String>,

        /// Ignore saved cluster.conf and probe only the local host
        #[arg(long, default_value_t = false)]
        local: bool,

        /// Shared cluster auth token (or env CRUSHGRID_TOKEN)
        #[arg(long, env = "CRUSHGRID_TOKEN", default_value = "")]
        token: String,

        /// Transport security mode: aead (default) or auth-only
        #[arg(long)]
        security: Option<String>,
    },

    /// Pack a directory or file tree into a deduplicated, multi-codec `.sqz` archive
    #[command(visible_aliases = ["archive", "zip"])]
    Pack {
        /// Source directory (or file) to archive
        source: PathBuf,

        /// Output `.sqz` archive path (defaults to `<source>.sqz`)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Exclude top-level folder or file names (repeatable)
        #[arg(long = "exclude")]
        exclude: Vec<String>,

        /// Human-friendly compression preset: fast, balanced (default), small, max
        #[arg(short = 'm', long, default_value = "balanced")]
        preset: String,

        /// Override codec: auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, lz4
        #[arg(long)]
        codec: Option<String>,

        /// Override codec level (zstd: 1..22, lzma2/bcj: 0..9, bzip3: 1..32 MiB, ppmd: 4..12)
        #[arg(short, long)]
        level: Option<i32>,

        /// Slab size (e.g. 4M, 8M, 16M) or 'auto'
        #[arg(long, default_value = "auto")]
        block_size: String,

        /// Disable BLAKE3 exact slab deduplication
        #[arg(long, default_value_t = false)]
        no_dedup: bool,

        /// Disable zero-CPU incompressible slab bypass
        #[arg(long, default_value_t = false)]
        no_raw_bypass: bool,

        #[command(flatten)]
        cluster_args: ClusterArgs,
    },

    /// Extract a `.sqz` directory archive in parallel via positional writes and per-slab XXH3 checks
    #[command(visible_aliases = ["extract", "unzip"])]
    Unpack {
        /// Input `.sqz` archive path
        input: PathBuf,

        /// Destination directory (defaults to archive stem)
        #[arg(short, long)]
        output: Option<PathBuf>,

        #[command(flatten)]
        cluster_args: ClusterArgs,
    },

    /// Inspect metadata, ratio, per-codec breakdown, dedup savings, and file list of an archive
    Inspect {
        /// Archive path (`.sqz`, `.hsq`, or seekable `.zst`)
        input: PathBuf,

        /// Print packed file paths inside `.sqz` directory archives (first 100 entries)
        #[arg(short, long, default_value_t = false)]
        list: bool,
    },

    /// Compress a single file across any number of local and remote devices
    Compress {
        /// Input file path
        input: PathBuf,

        /// Output archive path (defaults to `<input>.zst` or `<input>.sqz`)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Human-friendly compression preset: fast, balanced (default), small, max
        #[arg(short = 'm', long, default_value = "balanced")]
        preset: String,

        /// Override codec: auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, lz4
        #[arg(long)]
        codec: Option<String>,

        /// Override codec level (zstd: 1..22, lzma2/bcj: 0..9, bzip3: 1..32 MiB, ppmd: 4..12)
        #[arg(short, long)]
        level: Option<i32>,

        /// Container format: auto, zst (standard Zstd Seekable), or sqz (multi-codec + dedup + BLAKE3)
        #[arg(long, default_value = "auto")]
        format: String,

        /// Slab size (e.g. 4M, 8M, 16M) or 'auto'
        #[arg(long, default_value = "auto")]
        block_size: String,

        /// Disable BLAKE3 exact slab deduplication (`.sqz` only)
        #[arg(long, default_value_t = false)]
        no_dedup: bool,

        /// Disable zero-CPU incompressible slab bypass (`.sqz` only)
        #[arg(long, default_value_t = false)]
        no_raw_bypass: bool,

        #[command(flatten)]
        cluster_args: ClusterArgs,
    },

    /// Decompress a seekable `.zst` or `.sqz` file in parallel
    Decompress {
        /// Input archive path (seekable `.zst` or `.sqz`)
        input: PathBuf,

        /// Output file path (defaults to stripping archive extension)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Skip whole-file BLAKE3 verification on single-file `.sqz` decompression
        #[arg(long, default_value_t = false)]
        no_verify: bool,

        #[command(flatten)]
        cluster_args: ClusterArgs,
    },

    /// Run a head-to-head local vs cluster benchmark with BLAKE3 round-trip verification
    Bench {
        /// Input test file path
        input: PathBuf,

        /// Temporary directory for benchmark output files
        #[arg(long)]
        workdir: Option<PathBuf>,

        /// Human-friendly compression preset: fast, balanced (default), small, max
        #[arg(short = 'm', long, default_value = "balanced")]
        preset: String,

        /// Override codec: auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, lz4
        #[arg(long)]
        codec: Option<String>,

        /// Override codec level
        #[arg(short, long)]
        level: Option<i32>,

        /// Slab size (e.g. 2M, 8M) or 'auto'
        #[arg(long, default_value = "auto")]
        block_size: String,

        #[command(flatten)]
        cluster_args: ClusterArgs,
    },

    /// Measure raw multi-stream TCP + AEAD bidirectional wire throughput to remote workers
    NetBench {
        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        /// Remote node spec (repeatable)
        #[arg(long = "node")]
        node: Vec<String>,

        /// Comma-separated remote host:port targets
        #[arg(long)]
        nodes: Option<String>,

        /// Shared cluster auth token (or env CRUSHGRID_TOKEN)
        #[arg(long, env = "CRUSHGRID_TOKEN", default_value = "")]
        token: String,

        /// Transport security mode: aead (default) or auth-only
        #[arg(long)]
        security: Option<String>,

        /// Parallel TCP streams per node (1..=8, default 4)
        #[arg(long)]
        streams: Option<usize>,

        /// One-way MiB to transmit per node (bidirectional = 2x)
        #[arg(long, default_value_t = 32)]
        mib: usize,
    },
}

fn resolve_preset_codec(
    preset_str: &str,
    codec_opt: Option<&str>,
    level_opt: Option<i32>,
) -> Result<(Preset, CodecId, i32, bool)> {
    let preset = Preset::from_str(preset_str)?;
    let (def_codec, def_level, def_auto) = preset.default_codec_and_level();
    match codec_opt {
        None => Ok((preset, def_codec, level_opt.unwrap_or(def_level), def_auto)),
        Some(c) if c.eq_ignore_ascii_case("auto") => {
            Ok((preset, def_codec, level_opt.unwrap_or(def_level), true))
        }
        Some(c) => {
            let cid = CodecId::from_name(c)?;
            let lvl = cid.clamp_level(level_opt.unwrap_or_else(|| cid.default_level()));
            Ok((preset, cid, lvl, false))
        }
    }
}

fn default_pack_output(source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "archive".to_string());
    let parent = source.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.sqz", name))
}

fn default_extract_output(input: &Path, is_dir: bool) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| if is_dir { "extracted".into() } else { "output.bin".into() });
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let candidate = parent.join(&stem);
    if candidate == input {
        parent.join(format!("{}.out", stem))
    } else {
        candidate
    }
}

struct ResolvedCluster {
    specs: Vec<NodeSpec>,
    token: String,
    security: SecurityMode,
    wire_codec: WireCodec,
    mem_bytes: usize,
    streams: usize,
}

#[allow(clippy::too_many_arguments)]
fn resolve_cluster(
    cluster_path: Option<&PathBuf>,
    force_local: bool,
    node_args: &[String],
    nodes_csv: Option<&str>,
    cli_token: &str,
    cli_security: Option<&str>,
    cli_wire_codec: Option<&str>,
    cli_mem_limit: Option<&str>,
    cli_streams: Option<usize>,
    default_streams: usize,
) -> Result<ResolvedCluster> {
    let explicit_nodes = !node_args.is_empty() || nodes_csv.is_some();
    let effective_cluster_path = if force_local {
        None
    } else if let Some(p) = cluster_path {
        Some(p.clone())
    } else if !explicit_nodes {
        let auto = discover_default_cluster_config();
        if let Some(ref p) = auto {
            println!("[crushgrid] Auto-loaded cluster config: {}", p.display());
        }
        auto
    } else {
        None
    };

    let file_cfg = match effective_cluster_path {
        Some(ref p) => load_cluster_file(p)?,
        None => ClusterFileConfig::default(),
    };

    let streams = cli_streams
        .or(file_cfg.streams)
        .unwrap_or(default_streams)
        .clamp(1, 8);
    let token = if !cli_token.is_empty() {
        cli_token.to_string()
    } else {
        file_cfg.token.unwrap_or_default()
    };
    let sec_str = cli_security
        .map(|s| s.to_string())
        .or(file_cfg.security)
        .unwrap_or_else(|| "aead".to_string());
    let security = SecurityMode::from_str(&sec_str)?;

    let wire_str = cli_wire_codec
        .map(|s| s.to_string())
        .or(file_cfg.wire_codec)
        .unwrap_or_else(|| "auto".to_string());
    let wire_codec = WireCodec::from_str(&wire_str)?;

    let mem_bytes = match cli_mem_limit.map(|s| s.to_string()).or(file_cfg.mem_limit) {
        Some(m) => parse_size(&m)?,
        None => auto_mem_limit_bytes(),
    };

    let specs = if force_local {
        // Preserve explicit `--node local:threads=50%,mem=...` caps when `--local` is set!
        let local_overrides: Vec<NodeSpec> = collect_node_specs(node_args, nodes_csv, streams)?
            .into_iter()
            .filter(|n| n.is_local)
            .collect();
        if local_overrides.is_empty() {
            vec![NodeSpec::local_default()]
        } else {
            local_overrides
        }
    } else {
        let mut all_nodes = file_cfg.nodes;
        all_nodes.extend_from_slice(node_args);
        collect_node_specs(&all_nodes, nodes_csv, streams)?
    };

    Ok(ResolvedCluster {
        specs,
        token,
        security,
        wire_codec,
        mem_bytes,
        streams,
    })
}

fn require_token_if_remote(rc: &ResolvedCluster) -> Result<()> {
    if rc.specs.iter().any(|s| !s.is_local) && rc.token.is_empty() {
        bail!("remote nodes configured: set CRUSHGRID_TOKEN, pass --token, or define token= in --cluster");
    }
    Ok(())
}

fn collect_node_specs(node_args: &[String], nodes_csv: Option<&str>, default_streams: usize) -> Result<Vec<NodeSpec>> {
    let mut specs = Vec::new();
    for s in node_args {
        let mut ns = NodeSpec::parse(s)?;
        if !ns.is_local && !s.contains("streams=") && !s.contains("s=") {
            ns.streams = default_streams.clamp(1, 8);
        }
        specs.push(ns);
    }
    if let Some(csv) = nodes_csv {
        for part in csv.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            let mut ns = NodeSpec::parse(p)?;
            if !ns.is_local && !p.contains("streams=") && !p.contains("s=") {
                ns.streams = default_streams.clamp(1, 8);
            }
            specs.push(ns);
        }
    }
    if specs.is_empty() {
        specs.push(NodeSpec::local_default());
    }
    Ok(specs)
}

fn print_probe_table(probed: &[resource::ProbedNode]) {
    println!("\n=== crushgrid Cluster Probe ({} node(s)) ===", probed.len());
    println!(
        "{:<24} {:<10} {:<14} {:<32} {:<10} {:<12} {:<14}",
        "TARGET", "STATUS", "OS/ARCH", "CPU", "THREADS", "MEM (MAX)", "LINK"
    );
    println!("{}", "-".repeat(120));
    for p in probed {
        let status = if p.reachable { "ONLINE" } else { "OFFLINE" };
        let link = if p.spec.is_local {
            "LOCAL".to_string()
        } else if p.reachable {
            format!("{:.1}ms/{:.0}MB/s", p.rtt_ms, p.probe_bw_mbps)
        } else {
            p.error.clone().unwrap_or_else(|| "err".into())
        };
        let cpu: String = p.caps.cpu_brand.chars().take(31).collect();
        println!(
            "{:<24} {:<10} {:<14} {:<32} {:<10} {:<12} {:<14}",
            p.spec.target,
            status,
            p.caps.os_arch,
            cpu,
            format!("{}/{}", p.caps.max_threads, p.caps.total_threads),
            format!("{} MiB", p.caps.max_mem_mb),
            link
        );
    }
    println!();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli)
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Do { request, dry_run } => {
            let resolved_args = nl::parse_natural_tokens(&request)?;
            println!(
                "[crushgrid] Resolved: crushgrid {}",
                nl::format_resolved_command(&resolved_args)
            );
            if dry_run {
                return Ok(());
            }
            let mut argv = vec!["crushgrid".to_string()];
            argv.extend(resolved_args);
            let parsed = Cli::try_parse_from(argv)?;
            dispatch(parsed)
        }

        Commands::Init {
            output,
            nodes,
            security,
            force,
        } => {
            let _ = SecurityMode::from_str(&security)?;
            let remote_list: Vec<String> = nodes
                .as_deref()
                .map(|csv| {
                    csv.split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            run_init_wizard(output.as_deref(), &remote_list, &security, force)
        }

        Commands::Doctor => run_doctor(),

        Commands::Worker {
            bind,
            token,
            max_threads,
            max_mem,
            allow_auth_only,
        } => {
            if token.len() < 8 {
                bail!("security guardrail: --token must be at least 8 characters long");
            }
            let info = probe_local_system();
            let eff_threads = max_threads.unwrap_or(info.total_threads).clamp(1, info.total_threads);
            let max_mem_bytes = parse_size(&max_mem)?;
            run_worker(WorkerConfig {
                bind_addr: bind,
                token,
                max_threads: eff_threads,
                max_mem_bytes,
                max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
                allow_auth_only,
            })
        }

        Commands::Probe {
            cluster,
            node,
            nodes,
            local,
            token,
            security,
        } => {
            let rc = resolve_cluster(
                cluster.as_ref(),
                local,
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                None,
                None,
                None,
                2,
            )?;
            require_token_if_remote(&rc)?;
            let probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            print_probe_table(&probed);
            Ok(())
        }

        Commands::Inspect { input, list } => run_inspect(&input, list),

        Commands::Pack {
            source,
            output,
            exclude,
            preset,
            codec,
            level,
            block_size,
            no_dedup,
            no_raw_bypass,
            cluster_args: ca,
        } => {
            let (preset_id, codec_id, eff_level, auto_codec) =
                resolve_preset_codec(&preset, codec.as_deref(), level)?;
            let out_path = output.unwrap_or_else(|| default_pack_output(&source));
            let blk = if block_size.eq_ignore_ascii_case("auto") {
                None
            } else {
                Some(parse_size(&block_size)?)
            };
            let sched = ScheduleMode::from_str(&ca.schedule)?;
            let rc = resolve_cluster(
                ca.cluster.as_ref(),
                ca.local,
                &ca.node,
                ca.nodes.as_deref(),
                &ca.token,
                ca.security.as_deref(),
                ca.wire_codec.as_deref(),
                ca.mem_limit.as_deref(),
                ca.streams,
                2,
            )?;
            require_token_if_remote(&rc)?;

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if ca.pick {
                interactive_pick(&mut probed)?;
            } else {
                print_probe_table(&probed);
            }

            run_pack(PackParams {
                source_dir: &source,
                output_path: &out_path,
                excludes: &exclude,
                codec: codec_id,
                level: eff_level,
                preset: preset_id,
                auto_codec,
                block_size: blk,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !ca.no_hedge,
                dedup: !no_dedup,
                entropy_bypass: !no_raw_bypass,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;
            Ok(())
        }

        Commands::Unpack {
            input,
            output,
            cluster_args: ca,
        } => {
            let out_path = output.unwrap_or_else(|| default_extract_output(&input, true));
            let sched = ScheduleMode::from_str(&ca.schedule)?;
            let rc = resolve_cluster(
                ca.cluster.as_ref(),
                ca.local,
                &ca.node,
                ca.nodes.as_deref(),
                &ca.token,
                ca.security.as_deref(),
                ca.wire_codec.as_deref(),
                ca.mem_limit.as_deref(),
                ca.streams,
                2,
            )?;
            require_token_if_remote(&rc)?;
            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if ca.pick {
                interactive_pick(&mut probed)?;
            }
            run_unpack(DecompressParams {
                input_path: &input,
                output_path: &out_path,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !ca.no_hedge,
                verify: true,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;
            Ok(())
        }

        Commands::Compress {
            input,
            output,
            preset,
            codec,
            level,
            format,
            block_size,
            no_dedup,
            no_raw_bypass,
            cluster_args: ca,
        } => {
            let (preset_id, codec_id, eff_level, auto_codec) =
                resolve_preset_codec(&preset, codec.as_deref(), level)?;
            let container_fmt = match format.to_ascii_lowercase().as_str() {
                "auto" => {
                    if !auto_codec && codec_id == CodecId::Zstd {
                        ContainerFormat::ZstdSeekable
                    } else {
                        ContainerFormat::Sqz
                    }
                }
                "zst" | "zstd" => {
                    if auto_codec || codec_id != CodecId::Zstd {
                        bail!("--format zst requires --codec zstd (use --format sqz for multi-codec/bzip3/ppmd/lzma2)");
                    }
                    ContainerFormat::ZstdSeekable
                }
                "sqz" | "hsq" => ContainerFormat::Sqz,
                other => bail!("invalid --format '{}': use auto, zst, or sqz", other),
            };
            let out_path = output.unwrap_or_else(|| {
                let ext = match container_fmt {
                    ContainerFormat::ZstdSeekable => "zst",
                    ContainerFormat::Sqz => "sqz",
                };
                let mut s = input.as_os_str().to_os_string();
                s.push(format!(".{}", ext));
                PathBuf::from(s)
            });

            let blk = if block_size.eq_ignore_ascii_case("auto") {
                None
            } else {
                Some(parse_size(&block_size)?)
            };
            let sched = ScheduleMode::from_str(&ca.schedule)?;
            let rc = resolve_cluster(
                ca.cluster.as_ref(),
                ca.local,
                &ca.node,
                ca.nodes.as_deref(),
                &ca.token,
                ca.security.as_deref(),
                ca.wire_codec.as_deref(),
                ca.mem_limit.as_deref(),
                ca.streams,
                2,
            )?;
            require_token_if_remote(&rc)?;

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if ca.pick {
                interactive_pick(&mut probed)?;
            } else {
                print_probe_table(&probed);
            }

            run_compress(CompressParams {
                input_path: &input,
                output_path: &out_path,
                codec: codec_id,
                level: eff_level,
                preset: preset_id,
                auto_codec,
                format: container_fmt,
                block_size: blk,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !ca.no_hedge,
                dedup: !no_dedup,
                entropy_bypass: !no_raw_bypass,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;
            Ok(())
        }

        Commands::Decompress {
            input,
            output,
            no_verify,
            cluster_args: ca,
        } => {
            let out_path = output.unwrap_or_else(|| default_extract_output(&input, false));
            let sched = ScheduleMode::from_str(&ca.schedule)?;
            let rc = resolve_cluster(
                ca.cluster.as_ref(),
                ca.local,
                &ca.node,
                ca.nodes.as_deref(),
                &ca.token,
                ca.security.as_deref(),
                ca.wire_codec.as_deref(),
                ca.mem_limit.as_deref(),
                ca.streams,
                2,
            )?;
            require_token_if_remote(&rc)?;

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if ca.pick {
                interactive_pick(&mut probed)?;
            }

            run_decompress(DecompressParams {
                input_path: &input,
                output_path: &out_path,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !ca.no_hedge,
                verify: !no_verify,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;
            Ok(())
        }

        Commands::Bench {
            input,
            workdir,
            preset,
            codec,
            level,
            block_size,
            cluster_args: ca,
        } => {
            let (preset_id, codec_id, eff_level, auto_codec) =
                resolve_preset_codec(&preset, codec.as_deref(), level)?;
            let blk = if block_size.eq_ignore_ascii_case("auto") {
                None
            } else {
                Some(parse_size(&block_size)?)
            };
            let rc = resolve_cluster(
                ca.cluster.as_ref(),
                ca.local,
                &ca.node,
                ca.nodes.as_deref(),
                &ca.token,
                ca.security.as_deref(),
                ca.wire_codec.as_deref(),
                ca.mem_limit.as_deref(),
                ca.streams,
                2,
            )?;
            require_token_if_remote(&rc)?;
            let probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            print_probe_table(&probed);

            let dir = workdir.unwrap_or_else(|| {
                input
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            let orig_hash = hex_encode(&hash_file_blake3(&input).context("hashing input")?);
            println!("Input BLAKE3: {}\n", orig_hash);

            let fmt = if !auto_codec && codec_id == CodecId::Zstd {
                ContainerFormat::ZstdSeekable
            } else {
                ContainerFormat::Sqz
            };
            let ext = if fmt == ContainerFormat::ZstdSeekable { "zst" } else { "sqz" };
            let local_arc = dir.join(format!("bench_local.{}", ext));
            let cluster_arc = dir.join(format!("bench_cluster.{}", ext));
            let restored = dir.join("bench_restored.bin");

            let label = if auto_codec {
                format!("auto (preset={})", preset_id.name())
            } else {
                format!("{} L{}", codec_id.name(), eff_level)
            };

            println!(">>> [1/4] Baseline LOCAL-ONLY Compress ({}) ...", label);
            let local_c = run_compress(CompressParams {
                input_path: &input,
                output_path: &local_arc,
                codec: codec_id,
                level: eff_level,
                preset: preset_id,
                auto_codec,
                format: fmt,
                block_size: blk,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: ScheduleMode::LocalOnly,
                wire_codec: rc.wire_codec,
                hedge: false,
                dedup: false,
                entropy_bypass: false,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;

            println!(">>> [2/4] CLUSTER Compress ({}, sec={:?}, wire={:?}) ...", label, rc.security, rc.wire_codec);
            let cluster_c = run_compress(CompressParams {
                input_path: &input,
                output_path: &cluster_arc,
                codec: codec_id,
                level: eff_level,
                preset: preset_id,
                auto_codec,
                format: fmt,
                block_size: blk,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: ScheduleMode::ForceAll,
                wire_codec: rc.wire_codec,
                hedge: true,
                dedup: false,
                entropy_bypass: false,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;

            println!(">>> [3/4] Baseline LOCAL-ONLY Decompress ...");
            let local_d = run_decompress(DecompressParams {
                input_path: &cluster_arc,
                output_path: &restored,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: ScheduleMode::LocalOnly,
                wire_codec: rc.wire_codec,
                hedge: false,
                verify: true,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;

            println!(">>> [4/4] CLUSTER Decompress (Auto Cost-Aware) + Byte-for-Byte BLAKE3 Verify ...");
            let cluster_d = run_decompress(DecompressParams {
                input_path: &cluster_arc,
                output_path: &restored,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: ScheduleMode::Auto,
                wire_codec: rc.wire_codec,
                hedge: true,
                verify: true,
                token: &rc.token,
                nodes: &probed,
                quiet: false,
            })?;

            let restored_hash = hex_encode(&hash_file_blake3(&restored)?);
            if restored_hash != orig_hash {
                bail!("VERIFICATION FAILED! orig={} restored={}", orig_hash, restored_hash);
            }

            let _ = std::fs::remove_file(&local_arc);
            let _ = std::fs::remove_file(&cluster_arc);
            let _ = std::fs::remove_file(&restored);

            println!("\n================= HEAD-TO-HEAD BENCHMARK =================");
            println!(
                "  Codec / Preset    : {} | Security: {:?} | BLAKE3: VERIFIED EXACT MATCH",
                label, rc.security
            );
            println!(
                "  Compress Local    : {:7.3} s ({:7.2} MiB/s)",
                local_c.elapsed_secs, local_c.throughput_mbps
            );
            println!(
                "  Compress Cluster  : {:7.3} s ({:7.2} MiB/s)  --> {:.2}x SPEEDUP!",
                cluster_c.elapsed_secs,
                cluster_c.throughput_mbps,
                local_c.elapsed_secs / cluster_c.elapsed_secs
            );
            println!(
                "  Decompress Local  : {:7.3} s ({:7.2} MiB/s)",
                local_d.elapsed_secs, local_d.throughput_mbps
            );
            println!(
                "  Decompress Cluster: {:7.3} s ({:7.2} MiB/s)  --> {:.2}x vs local",
                cluster_d.elapsed_secs,
                cluster_d.throughput_mbps,
                local_d.elapsed_secs / cluster_d.elapsed_secs
            );
            println!("==========================================================\n");
            Ok(())
        }

        Commands::NetBench {
            cluster,
            node,
            nodes,
            token,
            security,
            streams,
            mib,
        } => {
            let rc = resolve_cluster(
                cluster.as_ref(),
                false,
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                None,
                None,
                streams,
                4,
            )?;
            require_token_if_remote(&rc)?;
            if rc.specs.iter().all(|s| s.is_local) {
                bail!("net-bench requires at least one remote node via --nodes, --node, or --cluster");
            }
            run_net_bench(&rc.specs, &rc.token, rc.security, mib, rc.streams)
        }
    }
}
