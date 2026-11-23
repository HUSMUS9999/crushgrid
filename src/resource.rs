use crate::protocol::WorkerCaps;
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

#[derive(Debug, Default, Clone)]
pub struct ClusterFileConfig {
    pub token: Option<String>,
    pub security: Option<String>,
    pub wire_codec: Option<String>,
    pub mem_limit: Option<String>,
    pub streams: Option<usize>,
    pub nodes: Vec<String>,
}

/// Load an N-node cluster config file (`cluster.conf`) supporting arbitrary numbers of LAN/Tailscale/Cloud workers.
pub fn load_cluster_file(path: &Path) -> Result<ClusterFileConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed reading cluster config {}", path.display()))?;
    let mut cfg = ClusterFileConfig::default();
    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("invalid syntax in {} line {}: expected key = value", path.display(), lineno + 1))?;
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match key.as_str() {
            "token" => cfg.token = Some(val),
            "security" => cfg.security = Some(val),
            "wire_codec" | "wire-codec" => cfg.wire_codec = Some(val),
            "mem_limit" | "mem-limit" => cfg.mem_limit = Some(val),
            "streams" => {
                let s: usize = val.parse().with_context(|| format!("invalid streams on line {}", lineno + 1))?;
                cfg.streams = Some(s.clamp(1, 8));
            }
            "node" => cfg.nodes.push(val),
            other => bail!("unknown key '{}' in {} line {}", other, path.display(), lineno + 1),
        }
    }
    Ok(cfg)
}

#[derive(Debug, Clone)]
pub struct LocalSysInfo {
    pub hostname: String,
    pub os_arch: String,
    pub cpu_brand: String,
    pub total_threads: usize,
    pub total_mem_mb: u32,
    pub avail_mem_mb: u32,
}

pub fn probe_local_system() -> LocalSysInfo {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );
    sys.refresh_memory();
    let total_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or_else(|_| sys.cpus().len().max(1));
    let cpu_brand = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let hostname = System::host_name().unwrap_or_else(|| "local".to_string());
    let os_arch = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);
    let total_mem_mb = (sys.total_memory() / (1024 * 1024)) as u32;
    let avail_mem_mb = (sys.available_memory() / (1024 * 1024)).max(256) as u32;

    LocalSysInfo {
        hostname,
        os_arch,
        cpu_brand,
        total_threads,
        total_mem_mb,
        avail_mem_mb,
    }
}

pub fn local_worker_caps(max_threads: Option<usize>, max_mem_bytes: Option<usize>) -> WorkerCaps {
    let info = probe_local_system();
    let eff_threads = max_threads
        .map(|t| t.clamp(1, info.total_threads))
        .unwrap_or(info.total_threads);
    let default_mem_mb = (info.avail_mem_mb / 2).clamp(256, 8192);
    let eff_mem_mb = max_mem_bytes
        .map(|b| ((b / (1024 * 1024)) as u32).clamp(64, info.total_mem_mb.max(256)))
        .unwrap_or(default_mem_mb);

    WorkerCaps {
        hostname: info.hostname,
        os_arch: info.os_arch,
        cpu_brand: info.cpu_brand,
        total_threads: info.total_threads as u16,
        max_threads: eff_threads as u16,
        avail_mem_mb: info.avail_mem_mb,
        max_mem_mb: eff_mem_mb,
    }
}

/// Parse human byte sizes like "512M", "4G", "64K", "100MB", "1048576".
pub fn parse_size(s: &str) -> Result<usize> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty size string");
    }
    let upper = s.to_ascii_uppercase();
    let (num_str, mult): (&str, f64) = if let Some(n) = upper.strip_suffix("GIB").or_else(|| upper.strip_suffix("GB")).or_else(|| upper.strip_suffix('G')) {
        (n, 1024.0 * 1024.0 * 1024.0)
    } else if let Some(n) = upper.strip_suffix("MIB").or_else(|| upper.strip_suffix("MB")).or_else(|| upper.strip_suffix('M')) {
        (n, 1024.0 * 1024.0)
    } else if let Some(n) = upper.strip_suffix("KIB").or_else(|| upper.strip_suffix("KB")).or_else(|| upper.strip_suffix('K')) {
        (n, 1024.0)
    } else if let Some(n) = upper.strip_suffix('B') {
        (n, 1.0)
    } else {
        (upper.as_str(), 1.0)
    };
    let val: f64 = num_str.trim().parse().with_context(|| format!("invalid size '{}'", s))?;
    if val <= 0.0 || !val.is_finite() {
        bail!("size must be positive: '{}'", s);
    }
    Ok((val * mult) as usize)
}

#[derive(Debug, Clone)]
pub enum ThreadAlloc {
    Auto,
    Max,
    Exact(usize),
    Percent(u8),
}

impl ThreadAlloc {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        if s == "auto" {
            Ok(Self::Auto)
        } else if s == "max" || s == "all" {
            Ok(Self::Max)
        } else if let Some(pct) = s.strip_suffix('%') {
            let p: u8 = pct.parse().with_context(|| format!("invalid thread percentage '{}'", s))?;
            if p == 0 || p > 100 {
                bail!("thread percentage must be 1..=100");
            }
            Ok(Self::Percent(p))
        } else {
            let n: usize = s.parse().with_context(|| format!("invalid thread count '{}'", s))?;
            if n == 0 {
                bail!("thread count must be >= 1");
            }
            Ok(Self::Exact(n))
        }
    }

    pub fn resolve(&self, max_avail: usize) -> usize {
        let max_avail = max_avail.max(1);
        match *self {
            Self::Auto => max_avail,
            Self::Max => max_avail,
            Self::Exact(n) => n.clamp(1, max_avail),
            Self::Percent(p) => ((max_avail * p as usize) / 100).max(1),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeSpec {
    /// "local" or "host:port"
    pub target: String,
    pub is_local: bool,
    pub threads: ThreadAlloc,
    pub mem_bytes: Option<usize>,
    /// Optional TX bandwidth cap in bytes/sec (e.g., bw=80M -> 80 MiB/s)
    pub bw_limit_bps: Option<usize>,
    /// Number of parallel full-duplex TCP streams for remote workers
    pub streams: usize,
    pub enabled: bool,
}

impl NodeSpec {
    pub fn local_default() -> Self {
        Self {
            target: "local".to_string(),
            is_local: true,
            threads: ThreadAlloc::Auto,
            mem_bytes: None,
            bw_limit_bps: None,
            streams: 1,
            enabled: true,
        }
    }

    /// Parse specs like:
    /// - "local"
    /// - "local:threads=10,mem=3G"
    /// - "192.168.100.40:7878"
    /// - "192.168.100.40:7878:threads=28,mem=6G,bw=100M,streams=4"
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty node spec");
        }

        let (target, opts_str) = if let Some(rest) = spec.strip_prefix("local") {
            if rest.is_empty() {
                ("local".to_string(), "")
            } else if let Some(o) = rest.strip_prefix(':') {
                ("local".to_string(), o)
            } else {
                bail!("invalid local node spec '{}'", spec);
            }
        } else {
            // host:port or host:port:k=v,k=v
            let parts: Vec<&str> = spec.splitn(3, ':').collect();
            match parts.len() {
                1 => (format!("{}:7878", parts[0]), ""),
                2 => {
                    // Could be host:port OR host:threads=8
                    if parts[1].contains('=') {
                        (format!("{}:7878", parts[0]), parts[1])
                    } else {
                        (format!("{}:{}", parts[0], parts[1]), "")
                    }
                }
                3 => (format!("{}:{}", parts[0], parts[1]), parts[2]),
                _ => unreachable!(),
            }
        };

        let is_local = target == "local";
        let mut node = Self {
            target,
            is_local,
            threads: ThreadAlloc::Auto,
            mem_bytes: None,
            bw_limit_bps: None,
            streams: if is_local { 1 } else { 2 },
            enabled: true,
        };

        if !opts_str.is_empty() {
            for kv in opts_str.split(',') {
                let kv = kv.trim();
                if kv.is_empty() {
                    continue;
                }
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("expected key=value in node option '{}'", kv))?;
                match k.trim().to_ascii_lowercase().as_str() {
                    "threads" | "t" | "cpu" => node.threads = ThreadAlloc::parse(v)?,
                    "mem" | "ram" | "memory" => node.mem_bytes = Some(parse_size(v)?),
                    "bw" | "bandwidth" => node.bw_limit_bps = Some(parse_size(v)?),
                    "streams" | "s" => {
                        let s: usize = v.parse().context("invalid streams value")?;
                        node.streams = s.clamp(1, 8);
                    }
                    other => bail!("unknown node option '{}' in '{}'", other, spec),
                }
            }
        }
        Ok(node)
    }
}

#[derive(Debug, Clone)]
pub struct ProbedNode {
    pub spec: NodeSpec,
    pub caps: WorkerCaps,
    pub rtt_ms: f64,
    pub probe_bw_mbps: f64,
    pub reachable: bool,
    pub error: Option<String>,
}

/// Interactive CLI resource picker: shows live probed cluster table and lets user choose
/// which devices to enable plus exact threads/RAM/bandwidth caps for each.
pub fn interactive_pick(probed: &mut [ProbedNode]) -> Result<()> {
    println!("\n=== squiz-archive Interactive Device & Resource Picker ===");
    println!(
        "{:<3} {:<22} {:<14} {:<28} {:<10} {:<10} {:<10}",
        "#", "NODE", "OS/ARCH", "CPU", "THREADS", "AVAIL RAM", "LINK"
    );
    println!("{}", "-".repeat(102));
    for (idx, p) in probed.iter().enumerate() {
        let link = if p.spec.is_local {
            "LOCAL".to_string()
        } else if p.reachable {
            format!("{:.1}ms/{:.0}MB/s", p.rtt_ms, p.probe_bw_mbps)
        } else {
            "OFFLINE".to_string()
        };
        let cpu_short: String = p.caps.cpu_brand.chars().take(27).collect();
        println!(
            "{:<3} {:<22} {:<14} {:<28} {:<10} {:<10} {:<10}",
            idx + 1,
            p.spec.target,
            p.caps.os_arch,
            cpu_short,
            format!("{}/{}", p.caps.max_threads, p.caps.total_threads),
            format!("{} MiB", p.caps.avail_mem_mb),
            link
        );
    }
    println!();

    let stdin = io::stdin();
    for (idx, p) in probed.iter_mut().enumerate() {
        if !p.reachable {
            p.spec.enabled = false;
            println!(
                "[{}] {} is offline ({}), skipping.",
                idx + 1,
                p.spec.target,
                p.error.as_deref().unwrap_or("unreachable")
            );
            continue;
        }
        print!(
            "[{}] Use {}? [Y/n] (max {}T, {} MiB): ",
            idx + 1,
            p.spec.target,
            p.caps.max_threads,
            p.caps.max_mem_mb
        );
        io::stdout().flush()?;
        let mut line = String::new();
        stdin.read_line(&mut line)?;
        let ans = line.trim().to_ascii_lowercase();
        if ans == "n" || ans == "no" {
            p.spec.enabled = false;
            continue;
        }
        p.spec.enabled = true;

        print!(
            "    Threads for {} (1..={}, or %, Enter for {}): ",
            p.spec.target,
            p.caps.max_threads,
            p.spec.threads.resolve(p.caps.max_threads as usize)
        );
        io::stdout().flush()?;
        line.clear();
        stdin.read_line(&mut line)?;
        if !line.trim().is_empty() {
            p.spec.threads = ThreadAlloc::parse(line.trim())?;
        }

        print!(
            "    RAM limit for {} (e.g. 2G, 512M, Enter for {} MiB): ",
            p.spec.target, p.caps.max_mem_mb
        );
        io::stdout().flush()?;
        line.clear();
        stdin.read_line(&mut line)?;
        if !line.trim().is_empty() {
            p.spec.mem_bytes = Some(parse_size(line.trim())?);
        }

        if !p.spec.is_local {
            print!(
                "    Bandwidth cap for {} (e.g. 80M, Enter for unlimited): ",
                p.spec.target
            );
            io::stdout().flush()?;
            line.clear();
            stdin.read_line(&mut line)?;
            if !line.trim().is_empty() {
                p.spec.bw_limit_bps = Some(parse_size(line.trim())?);
            }
        }
    }

    if !probed.iter().any(|p| p.spec.enabled && p.reachable) {
        bail!("no devices selected");
    }
    Ok(())
}
