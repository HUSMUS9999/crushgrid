mod archiver;
mod codec;
mod container;
mod io_engine;
mod pool;
mod protocol;
mod resource;
mod scheduler;
mod worker;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use codec::{CodecId, Preset};
use container::ContainerFormat;
use protocol::{DEFAULT_MAX_FRAME_BYTES, SecurityMode, WireCodec};
use resource::{
    ClusterFileConfig, NodeSpec, interactive_pick, load_cluster_file, parse_size,
    probe_local_system,
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
    name = "squiz-archive",
    version,
    about = "Distributed multi-node compression and archival CLI for LAN, VPN, and cloud hosts",
    long_about = "Distributed multi-node compression and archival CLI.\n\n\
Presets (no codec knowledge required):\n  \
  fast      Maximum speed (Zstd L3)\n  \
  balanced  Everyday speed and ratio (Zstd L9 + LDM, default)\n  \
  small     High ratio, fast multi-codec (Bzip3 on text/CSV, LZMA2+BCJ on binaries, LZMA2 L6 on mixed)\n  \
  max       Smallest archive (Bzip3 16M on text/code, LZMA2+BCJ L9 on binaries, LZMA2 L9 on mixed)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a secure multi-stream compute worker daemon with hard CPU/RAM ceilings
    Worker {
        /// Listen address (e.g. 0.0.0.0:7878 or your Tailscale IP:7878)
        #[arg(long, default_value = "0.0.0.0:7878")]
        bind: SocketAddr,

        /// Shared authentication token (recommended: set SQUIZ_TOKEN env var instead of CLI arg)
        #[arg(long, env = "SQUIZ_TOKEN")]
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

    /// Probe available nodes, CPU/RAM resources, RTT, and live link bandwidth
    Probe {
        /// Path to an N-node cluster config file (see cluster.conf.example)
        #[arg(long)]
        cluster: Option<PathBuf>,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

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

        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        /// Exclude top-level folder/file names (repeatable)
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

        /// Block size (e.g. 4M, 8M, 16M) or 'auto'
        #[arg(long, default_value = "auto")]
        block_size: String,

        /// Coordinator hard RAM limit (e.g. 2G, 4G, 512M)
        #[arg(long)]
        mem_limit: Option<String>,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        /// Launch interactive CLI device and resource picker
        #[arg(short = 'i', long, default_value_t = false)]
        pick: bool,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        #[arg(long)]
        security: Option<String>,

        #[arg(long, default_value = "auto")]
        schedule: String,

        /// Wire pre-shrink codec: auto (zstd1 on links <100 MiB/s, lz4 on >=100 MiB/s), zstd1, lz4, none
        #[arg(long)]
        wire_codec: Option<String>,

        #[arg(long, default_value_t = false)]
        no_hedge: bool,

        /// Disable BLAKE3 exact slab deduplication
        #[arg(long, default_value_t = false)]
        no_dedup: bool,

        /// Disable zero-CPU incompressible slab bypass
        #[arg(long, default_value_t = false)]
        no_raw_bypass: bool,

        #[arg(long)]
        streams: Option<usize>,
    },

    /// Extract a `.sqz` directory archive in parallel with positional writes & per-slab XXH3 verification
    #[command(visible_aliases = ["extract", "unzip"])]
    Unpack {
        /// Input `.sqz` archive path
        input: PathBuf,

        /// Destination directory (defaults to archive stem in current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        #[arg(long)]
        mem_limit: Option<String>,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        #[arg(short = 'i', long, default_value_t = false)]
        pick: bool,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        #[arg(long)]
        security: Option<String>,

        #[arg(long, default_value = "auto")]
        schedule: String,

        #[arg(long)]
        wire_codec: Option<String>,

        #[arg(long, default_value_t = false)]
        no_hedge: bool,

        #[arg(long)]
        streams: Option<usize>,
    },

    /// Inspect metadata, ratio, per-codec breakdown, dedup savings, and file list of an archive
    Inspect {
        input: PathBuf,

        #[arg(short, long, default_value_t = false)]
        list: bool,
    },

    /// Compress a single file across any number of local & remote devices
    Compress {
        input: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        /// Human-friendly compression preset: fast, balanced (default), small, max
        #[arg(short = 'm', long, default_value = "balanced")]
        preset: String,

        /// Override codec: auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, lz4
        #[arg(long)]
        codec: Option<String>,

        #[arg(short, long)]
        level: Option<i32>,

        /// Container format: auto, zst (standard Zstd Seekable), or sqz (multi-codec + dedup + BLAKE3)
        #[arg(long, default_value = "auto")]
        format: String,

        #[arg(long, default_value = "auto")]
        block_size: String,

        #[arg(long)]
        mem_limit: Option<String>,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        #[arg(short = 'i', long, default_value_t = false)]
        pick: bool,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        #[arg(long)]
        security: Option<String>,

        #[arg(long, default_value = "auto")]
        schedule: String,

        #[arg(long)]
        wire_codec: Option<String>,

        #[arg(long, default_value_t = false)]
        no_hedge: bool,

        #[arg(long, default_value_t = false)]
        no_dedup: bool,

        #[arg(long, default_value_t = false)]
        no_raw_bypass: bool,

        #[arg(long)]
        streams: Option<usize>,
    },

    /// Decompress a seekable `.zst` or `.sqz` archive in parallel across selected devices
    Decompress {
        input: PathBuf,

        /// Output file path (defaults to stripping `.sqz`/`.zst` extension)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        #[arg(long)]
        mem_limit: Option<String>,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        #[arg(short = 'i', long, default_value_t = false)]
        pick: bool,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        #[arg(long)]
        security: Option<String>,

        #[arg(long, default_value = "auto")]
        schedule: String,

        #[arg(long)]
        wire_codec: Option<String>,

        #[arg(long, default_value_t = false)]
        no_hedge: bool,

        /// Skip whole-file BLAKE3 verification on single-file .sqz decompress
        #[arg(long, default_value_t = false)]
        no_verify: bool,

        #[arg(long)]
        streams: Option<usize>,
    },

    /// Run a head-to-head cluster benchmark (local-only vs full cluster) with BLAKE3 round-trip verification
    Bench {
        input: PathBuf,

        #[arg(long)]
        workdir: Option<PathBuf>,

        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        /// Compression preset: fast, balanced, small, max
        #[arg(short = 'm', long, default_value = "balanced")]
        preset: String,

        /// Override codec: auto, zstd, bzip3, ppmd, lzma2, lzma2-bcj, lz4
        #[arg(long)]
        codec: Option<String>,

        #[arg(short, long)]
        level: Option<i32>,

        #[arg(long, default_value = "auto")]
        block_size: String,

        #[arg(long = "node")]
        node: Vec<String>,

        #[arg(long)]
        nodes: Option<String>,

        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        #[arg(long)]
        security: Option<String>,

        #[arg(long)]
        wire_codec: Option<String>,

        #[arg(long)]
        streams: Option<usize>,

        #[arg(long)]
        mem_limit: Option<String>,
    },

    /// Measure raw multi-stream TCP + AEAD bidirectional wire throughput to remote workers
    NetBench {
        /// Path to an N-node cluster config file
        #[arg(long)]
        cluster: Option<PathBuf>,

        #[arg(long = "node")]
        node: Vec<String>,

        /// Comma-separated remote host:port targets
        #[arg(long)]
        nodes: Option<String>,

        /// Shared auth token
        #[arg(long, env = "SQUIZ_TOKEN", default_value = "")]
        token: String,

        /// Security mode: aead or auth-only
        #[arg(long)]
        security: Option<String>,

        /// Parallel TCP streams per node
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
    node_args: &[String],
    nodes_csv: Option<&str>,
    cli_token: &str,
    cli_security: Option<&str>,
    cli_wire_codec: Option<&str>,
    cli_mem_limit: Option<&str>,
    cli_streams: Option<usize>,
    default_streams: usize,
) -> Result<ResolvedCluster> {
    let file_cfg = match cluster_path {
        Some(p) => load_cluster_file(p)?,
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

    let mem_str = cli_mem_limit
        .map(|s| s.to_string())
        .or(file_cfg.mem_limit)
        .unwrap_or_else(|| "2G".to_string());
    let mem_bytes = parse_size(&mem_str)?;

    let mut all_nodes = file_cfg.nodes;
    all_nodes.extend_from_slice(node_args);

    let specs = collect_node_specs(&all_nodes, nodes_csv, streams)?;
    Ok(ResolvedCluster {
        specs,
        token,
        security,
        wire_codec,
        mem_bytes,
        streams,
    })
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
    println!("\n=== squiz-archive Cluster Probe ({} node(s)) ===", probed.len());
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

    match cli.command {
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
            token,
            security,
        } => {
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                None,
                None,
                None,
                2,
            )?;
            let probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            print_probe_table(&probed);
            Ok(())
        }

        Commands::Inspect { input, list } => run_inspect(&input, list),

        Commands::Pack {
            source,
            output,
            cluster,
            exclude,
            preset,
            codec,
            level,
            block_size,
            mem_limit,
            node,
            nodes,
            pick,
            token,
            security,
            schedule,
            wire_codec,
            no_hedge,
            no_dedup,
            no_raw_bypass,
            streams,
        } => {
            let (preset_id, codec_id, eff_level, auto_codec) =
                resolve_preset_codec(&preset, codec.as_deref(), level)?;
            let out_path = output.unwrap_or_else(|| default_pack_output(&source));
            let blk = if block_size.eq_ignore_ascii_case("auto") {
                None
            } else {
                Some(parse_size(&block_size)?)
            };
            let sched = ScheduleMode::from_str(&schedule)?;
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                wire_codec.as_deref(),
                mem_limit.as_deref(),
                streams,
                2,
            )?;

            if rc.specs.iter().any(|s| !s.is_local) && rc.token.is_empty() {
                bail!("remote nodes configured: provide --token, SQUIZ_TOKEN, or token= in --cluster");
            }

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if pick {
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
                hedge: !no_hedge,
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
            cluster,
            mem_limit,
            node,
            nodes,
            pick,
            token,
            security,
            schedule,
            wire_codec,
            no_hedge,
            streams,
        } => {
            let out_path = output.unwrap_or_else(|| default_extract_output(&input, true));
            let sched = ScheduleMode::from_str(&schedule)?;
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                wire_codec.as_deref(),
                mem_limit.as_deref(),
                streams,
                2,
            )?;
            if rc.specs.iter().any(|s| !s.is_local) && rc.token.is_empty() {
                bail!("remote nodes configured: provide --token, SQUIZ_TOKEN, or token= in --cluster");
            }
            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if pick {
                interactive_pick(&mut probed)?;
            }
            run_unpack(DecompressParams {
                input_path: &input,
                output_path: &out_path,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !no_hedge,
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
            cluster,
            preset,
            codec,
            level,
            format,
            block_size,
            mem_limit,
            node,
            nodes,
            pick,
            token,
            security,
            schedule,
            wire_codec,
            no_hedge,
            no_dedup,
            no_raw_bypass,
            streams,
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
            let sched = ScheduleMode::from_str(&schedule)?;
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                wire_codec.as_deref(),
                mem_limit.as_deref(),
                streams,
                2,
            )?;

            if rc.specs.iter().any(|s| !s.is_local) && rc.token.is_empty() {
                bail!("remote nodes configured: provide --token, SQUIZ_TOKEN, or token= in --cluster");
            }

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if pick {
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
                hedge: !no_hedge,
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
            cluster,
            mem_limit,
            node,
            nodes,
            pick,
            token,
            security,
            schedule,
            wire_codec,
            no_hedge,
            no_verify,
            streams,
        } => {
            let out_path = output.unwrap_or_else(|| default_extract_output(&input, false));
            let sched = ScheduleMode::from_str(&schedule)?;
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                wire_codec.as_deref(),
                mem_limit.as_deref(),
                streams,
                2,
            )?;

            if rc.specs.iter().any(|s| !s.is_local) && rc.token.is_empty() {
                bail!("remote nodes configured: provide --token, SQUIZ_TOKEN, or token= in --cluster");
            }

            let mut probed = probe_nodes(&rc.specs, &rc.token, rc.security);
            if pick {
                interactive_pick(&mut probed)?;
            }

            run_decompress(DecompressParams {
                input_path: &input,
                output_path: &out_path,
                mem_limit_bytes: rc.mem_bytes,
                security: rc.security,
                schedule: sched,
                wire_codec: rc.wire_codec,
                hedge: !no_hedge,
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
            cluster,
            preset,
            codec,
            level,
            block_size,
            node,
            nodes,
            token,
            security,
            wire_codec,
            streams,
            mem_limit,
        } => {
            let (preset_id, codec_id, eff_level, auto_codec) =
                resolve_preset_codec(&preset, codec.as_deref(), level)?;
            let blk = if block_size.eq_ignore_ascii_case("auto") {
                None
            } else {
                Some(parse_size(&block_size)?)
            };
            let rc = resolve_cluster(
                cluster.as_ref(),
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                wire_codec.as_deref(),
                mem_limit.as_deref(),
                streams,
                2,
            )?;
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

            println!(">>> [1/4] Baseline LOCAL-ONLY Compress ({} L{}) ...", codec_id.name(), eff_level);
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

            println!(">>> [2/4] CLUSTER Compress ({} L{}, sec={:?}, wire={:?}) ...", codec_id.name(), eff_level, rc.security, rc.wire_codec);
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
                "  Codec / Level     : {} L{} (auto={}) | Security: {:?} | BLAKE3: VERIFIED EXACT MATCH",
                codec_id.name(),
                eff_level,
                auto_codec,
                rc.security
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
                &node,
                nodes.as_deref(),
                &token,
                security.as_deref(),
                None,
                None,
                streams,
                4,
            )?;
            if rc.specs.iter().all(|s| s.is_local) {
                bail!("net-bench requires at least one remote node via --nodes or --cluster");
            }
            run_net_bench(&rc.specs, &rc.token, rc.security, mib, rc.streams)
        }
    }
}
