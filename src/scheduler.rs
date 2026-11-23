use crate::archiver::{MultiFileStreamReader, MultiFileUnpacker, build_pack_plan};
use crate::codec::{
    CodecId, compress_block, decompress_block, is_likely_incompressible, wire_expand_zstd1,
    wire_shrink_zstd1,
};
use crate::container::{
    CHUNK_FLAG_COMPRESSED, CHUNK_FLAG_DEDUP_REF, CHUNK_FLAG_RAW_STORED, ChunkIndexEntry,
    ContainerFormat, PackedFileEntry, finalize_sqz, read_manifest, write_sqz_header_placeholder,
    write_zstd_seekable_footer,
};
use crate::io_engine::{read_exact_at, write_all_at};
use crate::pool::{BudgetGuard, ByteBudget};
use crate::protocol::{
    DEFAULT_MAX_FRAME_BYTES, FLAG_ALLOW_RESP_LZ4, FLAG_ALLOW_RESP_ZSTD1, FLAG_DECOMPRESS,
    FLAG_WIRE_LZ4, FLAG_WIRE_ZSTD1, FrameHeader, MsgType, SecurityMode, WireCodec, WorkerCaps,
    arm_quickack, client_handshake, tune_tcp_stream,
};
use crate::resource::{NodeSpec, ProbedNode, local_worker_caps};
use anyhow::{Context, Result, bail};
use crossbeam_channel::{RecvTimeoutError, bounded, unbounded};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xxhash_rust::xxh3::xxh3_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleMode {
    Auto,
    ForceAll,
    LocalOnly,
}

impl ScheduleMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "force-all" | "force" | "all" => Ok(Self::ForceAll),
            "local-only" | "local" => Ok(Self::LocalOnly),
            _ => bail!("invalid schedule mode '{}': use auto, force-all, or local-only", s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobSummary {
    pub elapsed_secs: f64,
    pub orig_bytes: u64,
    pub comp_bytes: u64,
    pub chunks: u64,
    pub block_size: usize,
    pub throughput_mbps: f64,
    pub ratio: f64,
    pub hedged_wins: u64,
    pub wire_saved_bytes: u64,
    pub dedup_saved_bytes: u64,
    pub raw_bypass_bytes: u64,
    pub blake3_hex: Option<String>,
    pub node_stats: Vec<NodeRunReport>,
}

#[derive(Debug, Clone)]
pub struct NodeRunReport {
    pub name: String,
    pub threads: usize,
    pub chunks_won: u64,
    pub orig_bytes: u64,
    pub wire_bytes: u64,
}

struct NodeStatsAtomic {
    name: String,
    threads: usize,
    chunks_won: AtomicU64,
    orig_bytes: AtomicU64,
    wire_bytes: AtomicU64,
}

impl NodeStatsAtomic {
    fn new(name: String, threads: usize) -> Self {
        Self {
            name,
            threads,
            chunks_won: AtomicU64::new(0),
            orig_bytes: AtomicU64::new(0),
            wire_bytes: AtomicU64::new(0),
        }
    }

    fn report(&self) -> NodeRunReport {
        NodeRunReport {
            name: self.name.clone(),
            threads: self.threads,
            chunks_won: self.chunks_won.load(Ordering::Relaxed),
            orig_bytes: self.orig_bytes.load(Ordering::Relaxed),
            wire_bytes: self.wire_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Airtime-Weighted AIMD Credit Controller (v6 Wi-Fi-Native):
/// - Separates pure network latency from worker `compute_us`
/// - Tracks live delivery rate (`delivery_rate_mbs`) and respects airtime-weighted credit ceiling
///   so slower Wi-Fi stations never hog shared AP airtime starving faster peers!
#[derive(Clone)]
struct AdaptiveCreditGate {
    inner: Arc<(Mutex<CreditState>, Condvar)>,
}

struct CreditState {
    inflight: usize,
    limit: usize,
    min_limit: usize,
    max_limit: usize,
    min_net_ms: f64,
    ema_total_ms: f64,
    ema_delivery_mbs: f64,
    samples: u64,
}

impl AdaptiveCreditGate {
    fn new(initial: usize, min_limit: usize, max_limit: usize) -> Self {
        let min_l = min_limit.max(1);
        let max_l = max_limit.max(min_l);
        let init = initial.clamp(min_l, max_l);
        Self {
            inner: Arc::new((
                Mutex::new(CreditState {
                    inflight: 0,
                    limit: init,
                    min_limit: min_l,
                    max_limit: max_l,
                    min_net_ms: f64::MAX,
                    ema_total_ms: 0.0,
                    ema_delivery_mbs: 10.0,
                    samples: 0,
                }),
                Condvar::new(),
            )),
        }
    }

    fn acquire(&self, shutdown: &AtomicBool) -> bool {
        let (lock, cvar) = &*self.inner;
        let mut st = lock.lock().unwrap();
        while st.inflight >= st.limit {
            if shutdown.load(Ordering::Relaxed) {
                return false;
            }
            let (guard, _) = cvar.wait_timeout(st, Duration::from_millis(15)).unwrap();
            st = guard;
        }
        st.inflight += 1;
        true
    }

    fn release_only(&self) {
        let (lock, cvar) = &*self.inner;
        let mut st = lock.lock().unwrap();
        st.inflight = st.inflight.saturating_sub(1);
        cvar.notify_all();
    }

    fn complete_with_timing(&self, pure_net_ms: f64, total_rtt_ms: f64, orig_bytes: usize) {
        let (lock, cvar) = &*self.inner;
        let mut st = lock.lock().unwrap();
        st.inflight = st.inflight.saturating_sub(1);
        st.samples += 1;
        let net = pure_net_ms.max(1.0);
        if net < st.min_net_ms {
            st.min_net_ms = net;
        }
        let sample_mbs = (orig_bytes as f64 / 1_048_576.0) / (net / 1000.0);
        if st.samples == 1 {
            st.ema_total_ms = total_rtt_ms;
            st.ema_delivery_mbs = sample_mbs;
        } else {
            st.ema_total_ms = st.ema_total_ms * 0.75 + total_rtt_ms * 0.25;
            st.ema_delivery_mbs = st.ema_delivery_mbs * 0.75 + sample_mbs * 0.25;
        }
        let bloat_threshold = st.min_net_ms * 2.5 + 180.0;
        let healthy_threshold = st.min_net_ms * 1.6 + 80.0;
        if net > bloat_threshold {
            st.limit = ((st.limit * 3) / 4).max(st.min_limit);
        } else if net <= healthy_threshold && st.limit < st.max_limit {
            st.limit = (st.limit + 2).min(st.max_limit);
        }
        cvar.notify_all();
    }

    fn ema_total_and_samples(&self) -> (f64, u64) {
        let st = self.inner.0.lock().unwrap();
        (st.ema_total_ms, st.samples)
    }
}

struct LocalPace {
    total_chunk_us: AtomicU64,
    samples: AtomicU64,
    threads: usize,
}

impl LocalPace {
    fn new(threads: usize) -> Self {
        Self {
            total_chunk_us: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            threads: threads.max(1),
        }
    }

    fn record(&self, micros: u64) {
        self.total_chunk_us.fetch_add(micros.max(1), Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
    }

    fn drain_eta_ms(&self, remaining_chunks: u64) -> Option<f64> {
        let n = self.samples.load(Ordering::Relaxed);
        if n < 4 {
            return None;
        }
        let avg_chunk_ms = (self.total_chunk_us.load(Ordering::Relaxed) as f64 / n as f64) / 1000.0;
        Some((remaining_chunks as f64 * avg_chunk_ms) / self.threads as f64)
    }
}

struct BandwidthPacer {
    bps: f64,
    start: Instant,
    sent_bytes: u64,
}

impl BandwidthPacer {
    fn new(bps: usize) -> Self {
        Self {
            bps: bps.max(1024) as f64,
            start: Instant::now(),
            sent_bytes: 0,
        }
    }

    fn pace(&mut self, bytes: usize) {
        self.sent_bytes += bytes as u64;
        let expected_secs = self.sent_bytes as f64 / self.bps;
        let elapsed = self.start.elapsed().as_secs_f64();
        if expected_secs > elapsed {
            let sleep_dur = Duration::from_secs_f64((expected_secs - elapsed).min(1.0));
            thread::sleep(sleep_dur);
        }
    }
}

struct WorkTask {
    chunk_id: u64,
    orig_offset: u64,
    orig_len: usize,
    expected_xxh3: u64,
    chunk_flags: u8,
    input: Arc<Vec<u8>>,
    _budget: Arc<BudgetGuard>,
}

struct InFlightEntry {
    task: Arc<WorkTask>,
    dispatched_at: Instant,
    hedged: bool,
}

struct CompletedChunk {
    chunk_id: u64,
    orig_offset: u64,
    orig_len: usize,
    orig_xxh3: u64,
    chunk_flags: u8,
    dedup_ref_chunk_id: Option<u64>,
    output: Vec<u8>,
    node_idx: usize,
    was_hedged: bool,
    wire_bytes: u64,
}

/// Probe all candidate nodes in parallel (BLAKE3 mutual auth + RTT + 2 MiB burst link speed).
pub fn probe_nodes(specs: &[NodeSpec], token: &str, security: SecurityMode) -> Vec<ProbedNode> {
    let mut handles = Vec::with_capacity(specs.len());
    for spec in specs.iter().cloned() {
        let tok = token.to_string();
        handles.push(thread::spawn(move || probe_single_node(spec, &tok, security)));
    }
    handles.into_iter().map(|h| h.join().unwrap()).collect()
}

fn probe_single_node(spec: NodeSpec, token: &str, security: SecurityMode) -> ProbedNode {
    if spec.is_local {
        let caps = local_worker_caps(None, spec.mem_bytes);
        return ProbedNode {
            spec,
            caps,
            rtt_ms: 0.0,
            probe_bw_mbps: 9999.0,
            reachable: true,
            error: None,
        };
    }

    let res: Result<(WorkerCaps, f64, f64)> = (|| {
        let addr = spec
            .target
            .to_socket_addrs()
            .with_context(|| format!("resolve {}", spec.target))?
            .next()
            .with_context(|| format!("no address for {}", spec.target))?;
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .with_context(|| format!("connect {}", spec.target))?;
        tune_tcp_stream(&stream)?;
        let (mut cipher, caps) = client_handshake(&mut stream, token, security, 0, 0, 0)?;

        let ping_t = Instant::now();
        let mut ping_buf = vec![0xA5u8; 64];
        cipher.write_frame(
            &mut stream,
            FrameHeader {
                msg_type: MsgType::ProbeReq,
                codec: 0,
                level: 0,
                flags: 0,
                chunk_id: 0,
                orig_len: 64,
                payload_len: 64,
                xxh3: 0,
            },
            &mut ping_buf,
        )?;
        let mut resp = Vec::new();
        let _ = cipher.read_frame_into(&mut stream, &mut resp, 4 * 1024 * 1024)?;
        let rtt_ms = ping_t.elapsed().as_secs_f64() * 1000.0;

        let bw_t = Instant::now();
        let mut bw_buf = vec![0x5Au8; 1024 * 1024];
        cipher.write_frame(
            &mut stream,
            FrameHeader {
                msg_type: MsgType::ProbeReq,
                codec: 0,
                level: 0,
                flags: 0,
                chunk_id: 1,
                orig_len: bw_buf.len() as u32,
                payload_len: bw_buf.len() as u32,
                xxh3: 0,
            },
            &mut bw_buf,
        )?;
        let _ = cipher.read_frame_into(&mut stream, &mut resp, 4 * 1024 * 1024)?;
        let bw_secs = bw_t.elapsed().as_secs_f64().max(1e-6);
        let probe_bw_mbps = (2.0 / bw_secs).min(9999.0);

        let _ = cipher.write_frame(
            &mut stream,
            FrameHeader {
                msg_type: MsgType::Shutdown,
                codec: 0,
                level: 0,
                flags: 0,
                chunk_id: 0,
                orig_len: 0,
                payload_len: 0,
                xxh3: 0,
            },
            &mut [],
        );
        Ok((caps, rtt_ms, probe_bw_mbps))
    })();

    match res {
        Ok((caps, rtt_ms, probe_bw_mbps)) => ProbedNode {
            spec,
            caps,
            rtt_ms,
            probe_bw_mbps,
            reachable: true,
            error: None,
        },
        Err(e) => ProbedNode {
            spec,
            caps: WorkerCaps {
                hostname: "-".into(),
                os_arch: "-".into(),
                cpu_brand: "-".into(),
                total_threads: 0,
                max_threads: 0,
                avail_mem_mb: 0,
                max_mem_mb: 0,
            },
            rtt_ms: 0.0,
            probe_bw_mbps: 0.0,
            reachable: false,
            error: Some(format!("{:#}", e)),
        },
    }
}

pub fn choose_block_size(
    explicit: Option<usize>,
    file_size: u64,
    codec: CodecId,
    level: i32,
    total_cluster_threads: usize,
    mem_limit_bytes: usize,
) -> usize {
    if let Some(b) = explicit {
        return b.clamp(64 * 1024, 32 * 1024 * 1024);
    }

    let threads = total_cluster_threads.max(1);
    let target_chunks = (threads * 3).max(8) as u64;
    let ideal = (file_size / target_chunks).max(1024 * 1024) as usize;

    let (min_b, max_b) = match codec {
        CodecId::Raw => (4 * 1024 * 1024, 16 * 1024 * 1024),
        CodecId::Lzma2 => {
            if level >= 6 {
                (1024 * 1024, 4 * 1024 * 1024)
            } else {
                (1024 * 1024, 4 * 1024 * 1024)
            }
        }
        CodecId::Zstd => {
            if level >= 15 {
                (2 * 1024 * 1024, 8 * 1024 * 1024)
            } else {
                (2 * 1024 * 1024, 16 * 1024 * 1024)
            }
        }
        CodecId::Lz4 => (2 * 1024 * 1024, 16 * 1024 * 1024),
    };

    let mem_cap = (mem_limit_bytes / (threads.max(4) * 2)).max(1024 * 1024);
    let chosen = ideal.clamp(min_b, max_b.min(mem_cap).max(min_b));
    ((chosen + 262_143) / 262_144) * 262_144
}

pub struct CompressParams<'a> {
    pub input_path: &'a Path,
    pub output_path: &'a Path,
    pub codec: CodecId,
    pub level: i32,
    pub format: ContainerFormat,
    pub block_size: Option<usize>,
    pub mem_limit_bytes: usize,
    pub security: SecurityMode,
    pub schedule: ScheduleMode,
    pub wire_codec: WireCodec,
    pub hedge: bool,
    pub dedup: bool,
    pub entropy_bypass: bool,
    pub token: &'a str,
    pub nodes: &'a [ProbedNode],
    pub quiet: bool,
}

enum InputSource {
    SingleFile(File),
    MultiFile(MultiFileStreamReader),
}

impl InputSource {
    fn read_slab(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::SingleFile(f) => {
                let mut total = 0usize;
                while total < buf.len() {
                    let n = f.read(&mut buf[total..])?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                Ok(total)
            }
            Self::MultiFile(r) => r.read_slab(buf),
        }
    }
}

pub fn run_compress(params: CompressParams<'_>) -> Result<JobSummary> {
    let label = params.input_path.display().to_string();
    let in_file = File::open(params.input_path)
        .with_context(|| format!("failed opening input {}", label))?;
    let total_orig_size = in_file.metadata()?.len();
    if total_orig_size == 0 {
        bail!("input file is empty");
    }
    run_compress_stream(
        params,
        InputSource::SingleFile(in_file),
        total_orig_size,
        Vec::new(),
        &label,
    )
}

pub struct PackParams<'a> {
    pub source_dir: &'a Path,
    pub output_path: &'a Path,
    pub excludes: &'a [String],
    pub codec: CodecId,
    pub level: i32,
    pub block_size: Option<usize>,
    pub mem_limit_bytes: usize,
    pub security: SecurityMode,
    pub schedule: ScheduleMode,
    pub wire_codec: WireCodec,
    pub hedge: bool,
    pub dedup: bool,
    pub entropy_bypass: bool,
    pub token: &'a str,
    pub nodes: &'a [ProbedNode],
    pub quiet: bool,
}

pub fn run_pack(params: PackParams<'_>) -> Result<JobSummary> {
    let mut exclude_abs: Vec<PathBuf> = Vec::new();
    if let Ok(canon) = std::fs::canonicalize(params.output_path) {
        exclude_abs.push(canon);
    } else if let Some(parent) = params.output_path.parent() {
        if let Ok(p_canon) = std::fs::canonicalize(parent) {
            if let Some(name) = params.output_path.file_name() {
                exclude_abs.push(p_canon.join(name));
            }
        }
    }

    if !params.quiet {
        println!(
            "[squiz-archive] Scanning {} (extension-class solid grouping + dedup)...",
            params.source_dir.display()
        );
    }
    let plan = build_pack_plan(params.source_dir, &exclude_abs, params.excludes)?;
    let regular_files = plan.files.iter().filter(|f| !f.is_dir).count();
    let dirs = plan.files.len() - regular_files;
    if plan.total_bytes == 0 {
        bail!("no readable non-empty files found in {}", params.source_dir.display());
    }
    if !params.quiet {
        println!(
            "[squiz-archive] Plan: {} files, {} dirs, {:.2} GiB ({:.2} MiB) | skipped/protected: {}",
            regular_files,
            dirs,
            plan.total_bytes as f64 / 1073741824.0,
            plan.total_bytes as f64 / 1048576.0,
            plan.skipped_count
        );
    }

    let reader = MultiFileStreamReader::new(&plan);
    let cp = CompressParams {
        input_path: params.source_dir,
        output_path: params.output_path,
        codec: params.codec,
        level: params.level,
        format: ContainerFormat::Sqz,
        block_size: params.block_size,
        mem_limit_bytes: params.mem_limit_bytes,
        security: params.security,
        schedule: params.schedule,
        wire_codec: params.wire_codec,
        hedge: params.hedge,
        dedup: params.dedup,
        entropy_bypass: params.entropy_bypass,
        token: params.token,
        nodes: params.nodes,
        quiet: params.quiet,
    };
    run_compress_stream(
        cp,
        InputSource::MultiFile(reader),
        plan.total_bytes,
        plan.files,
        &params.source_dir.display().to_string(),
    )
}

fn run_compress_stream(
    params: CompressParams<'_>,
    mut source: InputSource,
    total_orig_size: u64,
    packed_files: Vec<PackedFileEntry>,
    source_label: &str,
) -> Result<JobSummary> {
    let start = Instant::now();
    let active_nodes = select_active_nodes(params.nodes, params.schedule, params.codec, false)?;
    let has_remotes = active_nodes.iter().any(|n| !n.spec.is_local);
    let total_threads: usize = active_nodes
        .iter()
        .map(|n| effective_node_threads(n, has_remotes))
        .sum();
    let local_threads: usize = active_nodes
        .iter()
        .filter(|n| n.spec.is_local)
        .map(|n| effective_node_threads(n, has_remotes))
        .sum();

    let block_size = choose_block_size(
        params.block_size,
        total_orig_size,
        params.codec,
        params.level,
        total_threads,
        params.mem_limit_bytes,
    );
    let total_chunks = (total_orig_size + block_size as u64 - 1) / block_size as u64;

    // Dedup & zero-CPU raw slab bypass require .sqz v2 container (keep .zst 100% pure Zstd frames!)
    let allow_sqz_smart = params.format == ContainerFormat::Sqz;
    let use_dedup = allow_sqz_smart && params.dedup;
    let use_entropy_bypass = allow_sqz_smart && params.entropy_bypass;

    if !params.quiet {
        let ldm_tag = if params.codec == CodecId::Zstd { " (LDM)" } else { "" };
        println!(
            "[squiz-archive] Compress {} ({:.2} MiB) -> {} | codec={} L{}{} | fmt={:?} | blk={:.2} MiB ({} chunks) | nodes={} ({}T) | sec={:?} | wire={:?} | dedup={} | raw-bypass={}",
            source_label,
            total_orig_size as f64 / 1048576.0,
            params.output_path.display(),
            params.codec.name(),
            params.level,
            ldm_tag,
            params.format,
            block_size as f64 / 1048576.0,
            total_chunks,
            active_nodes.len(),
            total_threads,
            params.security,
            params.wire_codec,
            use_dedup,
            use_entropy_bypass
        );
    }

    let mem_budget = ByteBudget::new(params.mem_limit_bytes);
    let (work_tx, work_rx) = unbounded::<Arc<WorkTask>>();
    let (res_tx, res_rx) = bounded::<CompletedChunk>(total_threads * 2 + 32);

    let reader_done = Arc::new(AtomicBool::new(false));
    let job_done = Arc::new(AtomicBool::new(false));
    let hedged_wins = Arc::new(AtomicU64::new(0));
    let wire_saved_bytes = Arc::new(AtomicU64::new(0));
    let dedup_saved_bytes = Arc::new(AtomicU64::new(0));
    let raw_bypass_bytes = Arc::new(AtomicU64::new(0));
    let chunks_completed_counter = Arc::new(AtomicU64::new(0));
    let local_pace = Arc::new(LocalPace::new(local_threads));
    let active_sockets: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    let completed_set: Arc<Mutex<HashSet<u64>>> =
        Arc::new(Mutex::new(HashSet::with_capacity((total_chunks as usize).min(262_144))));
    let in_flight_remote: Arc<Mutex<HashMap<u64, InFlightEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Airtime-Weighted Credit Ceilings (v6 Wi-Fi-Native):
    // Compute each remote node's airtime efficiency score = probe_bw_mbps * eff_threads
    let remote_scores: Vec<f64> = active_nodes
        .iter()
        .map(|n| {
            if n.spec.is_local {
                0.0
            } else {
                let t = effective_node_threads(n, has_remotes) as f64;
                n.probe_bw_mbps.max(1.0) * t
            }
        })
        .collect();
    let max_remote_score = remote_scores
        .iter()
        .copied()
        .fold(1.0_f64, f64::max);

    let mut stats_vec: Vec<Arc<NodeStatsAtomic>> = Vec::with_capacity(active_nodes.len());
    for n in &active_nodes {
        let t = effective_node_threads(n, has_remotes);
        let label = if n.spec.is_local {
            format!("local ({})", n.caps.hostname)
        } else {
            format!("{} ({})", n.spec.target, n.caps.hostname)
        };
        stats_vec.push(Arc::new(NodeStatsAtomic::new(label, t)));
    }
    // Virtual stat index for instant dedup/raw bypass
    let local_node_idx = active_nodes
        .iter()
        .position(|n| n.spec.is_local)
        .unwrap_or(0);

    let mut worker_handles = Vec::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let eff_threads = effective_node_threads(node, has_remotes);
        let eff_mem_mb = node
            .spec
            .mem_bytes
            .map(|b| (b / (1024 * 1024)).max(64) as u32)
            .unwrap_or(node.caps.max_mem_mb)
            .min(node.caps.max_mem_mb.max(64));

        if node.spec.is_local {
            worker_handles.push(spawn_local_workers(
                node_idx,
                eff_threads,
                params.codec,
                params.level,
                false,
                params.hedge,
                work_rx.clone(),
                res_tx.clone(),
                reader_done.clone(),
                job_done.clone(),
                completed_set.clone(),
                in_flight_remote.clone(),
                local_pace.clone(),
            ));
        } else {
            let resolved_wire = params.wire_codec.resolve(node.probe_bw_mbps);
            // Airtime weight in [0.35, 1.0]: faster high-core peers get full credit ceilings,
            // slower peers get proportionally moderated ceilings so they don't starve faster links.
            let airtime_weight = (remote_scores[node_idx] / max_remote_score).clamp(0.35, 1.0);
            worker_handles.push(spawn_remote_worker_node(
                node_idx,
                node.spec.clone(),
                eff_threads,
                eff_mem_mb,
                block_size,
                total_chunks,
                local_threads > 0,
                airtime_weight,
                params.codec,
                params.level,
                false,
                resolved_wire,
                params.security,
                params.token.to_string(),
                work_tx.clone(),
                work_rx.clone(),
                res_tx.clone(),
                job_done.clone(),
                completed_set.clone(),
                in_flight_remote.clone(),
                chunks_completed_counter.clone(),
                local_pace.clone(),
                wire_saved_bytes.clone(),
                active_sockets.clone(),
            ));
        }
    }

    let out_path = params.output_path.to_path_buf();
    let format = params.format;
    let codec = params.codec;
    let level = params.level;
    let stats_writer = stats_vec.clone();
    let completed_writer = completed_set.clone();
    let inflight_writer = in_flight_remote.clone();
    let hedged_writer = hedged_wins.clone();
    let job_done_writer = job_done.clone();
    let chunks_done_writer = chunks_completed_counter.clone();
    let sockets_writer = active_sockets.clone();
    let quiet_w = params.quiet;
    let dedup_w = dedup_saved_bytes.clone();
    let raw_w = raw_bypass_bytes.clone();

    let (b3_tx, b3_rx) = bounded::<[u8; 32]>(1);

    let writer_handle = thread::spawn(move || -> Result<u64> {
        let mut out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&out_path)
            .with_context(|| format!("failed creating output {}", out_path.display()))?;

        if format == ContainerFormat::Sqz {
            write_sqz_header_placeholder(&mut out_file)?;
        }

        let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, out_file);
        let mut comp_cursor: u64 = if format == ContainerFormat::Sqz { 80 } else { 0 };
        let mut pending: BTreeMap<u64, CompletedChunk> = BTreeMap::new();
        let mut entries: Vec<ChunkIndexEntry> = Vec::with_capacity(total_chunks as usize);
        let mut next_id = 0u64;
        let mut last_progress = Instant::now();
        let mut written_orig = 0u64;

        while next_id < total_chunks {
            let chunk = match res_rx.recv() {
                Ok(c) => c,
                Err(_) => {
                    bail!(
                        "all workers exited before completing chunk {}/{}",
                        next_id,
                        total_chunks
                    )
                }
            };

            let won = {
                let mut done = completed_writer.lock().unwrap();
                done.insert(chunk.chunk_id)
            };
            if !won {
                continue;
            }
            chunks_done_writer.fetch_add(1, Ordering::Relaxed);
            {
                let mut inf = inflight_writer.lock().unwrap();
                inf.remove(&chunk.chunk_id);
            }
            if chunk.was_hedged {
                hedged_writer.fetch_add(1, Ordering::Relaxed);
            }

            let st = &stats_writer[chunk.node_idx];
            st.chunks_won.fetch_add(1, Ordering::Relaxed);
            st.orig_bytes.fetch_add(chunk.orig_len as u64, Ordering::Relaxed);
            st.wire_bytes.fetch_add(chunk.wire_bytes, Ordering::Relaxed);

            pending.insert(chunk.chunk_id, chunk);
            while let Some(ready) = pending.remove(&next_id) {
                if let Some(ref_id) = ready.dedup_ref_chunk_id {
                    // Exact BLAKE3 slab duplicate -> 0 bytes written to disk!
                    // Point directly at the earlier stored frame's (comp_offset, comp_len, flags)!
                    let target = &entries[ref_id as usize];
                    entries.push(ChunkIndexEntry {
                        chunk_id: ready.chunk_id,
                        comp_offset: target.comp_offset,
                        comp_len: target.comp_len,
                        orig_offset: ready.orig_offset,
                        orig_len: ready.orig_len as u32,
                        xxh3_64: ready.orig_xxh3,
                        chunk_flags: target.chunk_flags | CHUNK_FLAG_DEDUP_REF,
                    });
                } else {
                    writer.write_all(&ready.output)?;
                    let comp_len = ready.output.len() as u32;
                    entries.push(ChunkIndexEntry {
                        chunk_id: ready.chunk_id,
                        comp_offset: comp_cursor,
                        comp_len,
                        orig_offset: ready.orig_offset,
                        orig_len: ready.orig_len as u32,
                        xxh3_64: ready.orig_xxh3,
                        chunk_flags: ready.chunk_flags,
                    });
                    comp_cursor += comp_len as u64;
                }
                written_orig += ready.orig_len as u64;
                next_id += 1;

                if !quiet_w && total_orig_size >= 512 * 1024 * 1024 && last_progress.elapsed() >= Duration::from_secs(3) {
                    let secs = start.elapsed().as_secs_f64().max(0.1);
                    let pct = (written_orig as f64 * 100.0) / total_orig_size as f64;
                    let mibs = (written_orig as f64 / 1048576.0) / secs;
                    let ratio = written_orig as f64 / comp_cursor.max(1) as f64;
                    let eta = ((total_orig_size.saturating_sub(written_orig)) as f64 / 1048576.0) / mibs.max(0.1);
                    println!(
                        "  [progress] {:5.1}% | {:.2}/{:.2} GiB -> {:.2} GiB ({:.2}x) | {:.1} MiB/s | dedup={:.1} MiB | raw-skip={:.1} MiB | ETA {:.0}s",
                        pct,
                        written_orig as f64 / 1073741824.0,
                        total_orig_size as f64 / 1073741824.0,
                        comp_cursor as f64 / 1073741824.0,
                        ratio,
                        mibs,
                        dedup_w.load(Ordering::Relaxed) as f64 / 1048576.0,
                        raw_w.load(Ordering::Relaxed) as f64 / 1048576.0,
                        eta
                    );
                    last_progress = Instant::now();
                }
            }
        }

        job_done_writer.store(true, Ordering::Release);
        shutdown_all_sockets(&sockets_writer);

        writer.flush()?;
        let mut out_file = writer.into_inner()?;

        match format {
            ContainerFormat::ZstdSeekable => {
                write_zstd_seekable_footer(&mut out_file, &entries)?;
            }
            ContainerFormat::Sqz => {
                let hash = b3_rx.recv().unwrap_or([0u8; 32]);
                finalize_sqz(
                    &mut out_file,
                    codec,
                    level,
                    block_size as u32,
                    total_orig_size,
                    hash,
                    &entries,
                    &packed_files,
                )?;
            }
        }

        let final_len = out_file.metadata()?.len();
        Ok(final_len)
    });

    // Reader loop: sequential slab read + streaming BLAKE3 + exact BLAKE3 dedup + zero-CPU incompressible bypass!
    let mut blake3_hasher = blake3::Hasher::new();
    let mut dedup_index: HashMap<[u8; 32], u64> = HashMap::new();
    let mut offset = 0u64;
    let mut chunk_id = 0u64;

    while offset < total_orig_size {
        let to_read = (total_orig_size - offset).min(block_size as u64) as usize;
        let guard = Arc::new(mem_budget.acquire(to_read));
        let mut buf = vec![0u8; to_read];
        let got = source.read_slab(&mut buf)?;
        if got < to_read {
            buf.truncate(got);
        }
        let actual_len = buf.len();
        if actual_len == 0 {
            break;
        }
        blake3_hasher.update(&buf);
        let xxh = xxh3_64(&buf);

        // 1. Exact Chunk-Level BLAKE3 Deduplication (0 CPU, 0 Wi-Fi, 0 Disk!)
        if use_dedup {
            let slab_digest = *blake3::hash(&buf).as_bytes();
            if let Some(&prev_chunk_id) = dedup_index.get(&slab_digest) {
                dedup_saved_bytes.fetch_add(actual_len as u64, Ordering::Relaxed);
                drop(buf);
                drop(guard);
                res_tx.send(CompletedChunk {
                    chunk_id,
                    orig_offset: offset,
                    orig_len: actual_len,
                    orig_xxh3: xxh,
                    chunk_flags: CHUNK_FLAG_DEDUP_REF,
                    dedup_ref_chunk_id: Some(prev_chunk_id),
                    output: Vec::new(),
                    node_idx: local_node_idx,
                    was_hedged: false,
                    wire_bytes: 0,
                })?;
                offset += actual_len as u64;
                chunk_id += 1;
                continue;
            }
            dedup_index.insert(slab_digest, chunk_id);
        }

        // 2. Zero-CPU Incompressible Slab Bypass (<0.05 ms entropy probe -> skip heavy codec on .7z/.mp4/.jpg!)
        if use_entropy_bypass && is_likely_incompressible(&buf) {
            raw_bypass_bytes.fetch_add(actual_len as u64, Ordering::Relaxed);
            drop(guard);
            res_tx.send(CompletedChunk {
                chunk_id,
                orig_offset: offset,
                orig_len: actual_len,
                orig_xxh3: xxh,
                chunk_flags: CHUNK_FLAG_RAW_STORED,
                dedup_ref_chunk_id: None,
                output: buf,
                node_idx: local_node_idx,
                was_hedged: false,
                wire_bytes: 0,
            })?;
            offset += actual_len as u64;
            chunk_id += 1;
            continue;
        }

        let task = Arc::new(WorkTask {
            chunk_id,
            orig_offset: offset,
            orig_len: actual_len,
            expected_xxh3: xxh,
            chunk_flags: CHUNK_FLAG_COMPRESSED,
            input: Arc::new(buf),
            _budget: guard,
        });
        work_tx.send(task)?;
        offset += actual_len as u64;
        chunk_id += 1;
    }

    let final_b3 = *blake3_hasher.finalize().as_bytes();
    let _ = b3_tx.send(final_b3);
    reader_done.store(true, Ordering::Release);
    drop(work_tx);
    drop(res_tx);

    let comp_bytes = writer_handle.join().unwrap()?;
    let elapsed = start.elapsed().as_secs_f64().max(1e-6);

    job_done.store(true, Ordering::Release);
    shutdown_all_sockets(&active_sockets);
    for h in worker_handles {
        let _ = h.join();
    }

    let throughput_mbps = (total_orig_size as f64 / 1048576.0) / elapsed;
    let ratio = total_orig_size as f64 / comp_bytes.max(1) as f64;
    let b3_hex = hex_encode(&final_b3);

    let summary = JobSummary {
        elapsed_secs: elapsed,
        orig_bytes: total_orig_size,
        comp_bytes,
        chunks: total_chunks,
        block_size,
        throughput_mbps,
        ratio,
        hedged_wins: hedged_wins.load(Ordering::Relaxed),
        wire_saved_bytes: wire_saved_bytes.load(Ordering::Relaxed),
        dedup_saved_bytes: dedup_saved_bytes.load(Ordering::Relaxed),
        raw_bypass_bytes: raw_bypass_bytes.load(Ordering::Relaxed),
        blake3_hex: Some(b3_hex),
        node_stats: stats_vec.iter().map(|s| s.report()).collect(),
    };

    if !params.quiet {
        print_job_summary("COMPRESS", &summary);
    }
    Ok(summary)
}

pub struct DecompressParams<'a> {
    pub input_path: &'a Path,
    pub output_path: &'a Path,
    pub mem_limit_bytes: usize,
    pub security: SecurityMode,
    pub schedule: ScheduleMode,
    pub wire_codec: WireCodec,
    pub hedge: bool,
    pub verify: bool,
    pub token: &'a str,
    pub nodes: &'a [ProbedNode],
    pub quiet: bool,
}

enum ExtractSink {
    SingleFile(Arc<File>),
    MultiFile(MultiFileUnpacker),
}

impl ExtractSink {
    fn write_slab(&self, orig_offset: u64, data: &[u8]) -> Result<()> {
        match self {
            Self::SingleFile(f) => write_all_at(f, data, orig_offset),
            Self::MultiFile(u) => u.write_slab(orig_offset, data),
        }
    }
}

pub fn run_decompress(params: DecompressParams<'_>) -> Result<JobSummary> {
    run_extract_internal(params, false)
}

pub fn run_unpack(params: DecompressParams<'_>) -> Result<JobSummary> {
    run_extract_internal(params, true)
}

fn run_extract_internal(params: DecompressParams<'_>, is_dir_unpack: bool) -> Result<JobSummary> {
    let start = Instant::now();
    let mut in_file = File::open(params.input_path)
        .with_context(|| format!("failed opening archive {}", params.input_path.display()))?;
    let comp_bytes = in_file.metadata()?.len();
    let manifest = read_manifest(&mut in_file)?;
    let total_chunks = manifest.entries.len() as u64;
    let total_orig_size = manifest.total_orig_size;

    let active_nodes = select_active_nodes(params.nodes, params.schedule, manifest.codec, true)?;
    let has_remotes = active_nodes.iter().any(|n| !n.spec.is_local);
    let total_threads: usize = active_nodes
        .iter()
        .map(|n| effective_node_threads(n, has_remotes))
        .sum();
    let local_threads: usize = active_nodes
        .iter()
        .filter(|n| n.spec.is_local)
        .map(|n| effective_node_threads(n, has_remotes))
        .sum();
    let max_block = manifest
        .entries
        .iter()
        .map(|e| e.orig_len as usize)
        .max()
        .unwrap_or(1024 * 1024);

    if !params.quiet {
        println!(
            "[squiz-archive] {} {} ({:.2} MiB -> {:.2} MiB) | codec={} | fmt={:?} | chunks={} | files={} | nodes={} ({}T) | sched={:?}",
            if is_dir_unpack { "Unpack" } else { "Decompress" },
            params.input_path.display(),
            comp_bytes as f64 / 1048576.0,
            total_orig_size as f64 / 1048576.0,
            manifest.codec.name(),
            manifest.format,
            total_chunks,
            manifest.files.len(),
            active_nodes.len(),
            total_threads,
            params.schedule
        );
    }

    let sink = if is_dir_unpack || !manifest.files.is_empty() {
        if manifest.files.is_empty() {
            bail!("archive does not contain a directory file manifest; use `decompress` for single-file archives");
        }
        ExtractSink::MultiFile(MultiFileUnpacker::prepare(params.output_path, &manifest.files)?)
    } else {
        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(params.output_path)
            .with_context(|| format!("failed creating output {}", params.output_path.display()))?;
        out_file.set_len(total_orig_size)?;
        ExtractSink::SingleFile(Arc::new(out_file))
    };
    let is_single_file_sink = matches!(sink, ExtractSink::SingleFile(_));

    let mem_budget = ByteBudget::new(params.mem_limit_bytes);
    let (work_tx, work_rx) = unbounded::<Arc<WorkTask>>();
    let (res_tx, res_rx) = bounded::<CompletedChunk>(total_threads * 2 + 16);

    let reader_done = Arc::new(AtomicBool::new(false));
    let job_done = Arc::new(AtomicBool::new(false));
    let hedged_wins = Arc::new(AtomicU64::new(0));
    let wire_saved_bytes = Arc::new(AtomicU64::new(0));
    let chunks_completed_counter = Arc::new(AtomicU64::new(0));
    let local_pace = Arc::new(LocalPace::new(local_threads));
    let active_sockets: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    let completed_set: Arc<Mutex<HashSet<u64>>> =
        Arc::new(Mutex::new(HashSet::with_capacity((total_chunks as usize).min(262_144))));
    let in_flight_remote: Arc<Mutex<HashMap<u64, InFlightEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut stats_vec: Vec<Arc<NodeStatsAtomic>> = Vec::with_capacity(active_nodes.len());
    for n in &active_nodes {
        let t = effective_node_threads(n, has_remotes);
        let label = if n.spec.is_local {
            format!("local ({})", n.caps.hostname)
        } else {
            format!("{} ({})", n.spec.target, n.caps.hostname)
        };
        stats_vec.push(Arc::new(NodeStatsAtomic::new(label, t)));
    }
    let local_node_idx = active_nodes
        .iter()
        .position(|n| n.spec.is_local)
        .unwrap_or(0);

    let mut worker_handles = Vec::new();
    for (node_idx, node) in active_nodes.iter().enumerate() {
        let eff_threads = effective_node_threads(node, has_remotes);
        let eff_mem_mb = node
            .spec
            .mem_bytes
            .map(|b| (b / (1024 * 1024)).max(64) as u32)
            .unwrap_or(node.caps.max_mem_mb)
            .min(node.caps.max_mem_mb.max(64));

        if node.spec.is_local {
            worker_handles.push(spawn_local_workers(
                node_idx,
                eff_threads,
                manifest.codec,
                0,
                true,
                params.hedge,
                work_rx.clone(),
                res_tx.clone(),
                reader_done.clone(),
                job_done.clone(),
                completed_set.clone(),
                in_flight_remote.clone(),
                local_pace.clone(),
            ));
        } else {
            let resolved_wire = params.wire_codec.resolve(node.probe_bw_mbps);
            worker_handles.push(spawn_remote_worker_node(
                node_idx,
                node.spec.clone(),
                eff_threads,
                eff_mem_mb,
                max_block,
                total_chunks,
                local_threads > 0,
                1.0,
                manifest.codec,
                0,
                true,
                resolved_wire,
                params.security,
                params.token.to_string(),
                work_tx.clone(),
                work_rx.clone(),
                res_tx.clone(),
                job_done.clone(),
                completed_set.clone(),
                in_flight_remote.clone(),
                chunks_completed_counter.clone(),
                local_pace.clone(),
                wire_saved_bytes.clone(),
                active_sockets.clone(),
            ));
        }
    }

    let stats_w = stats_vec.clone();
    let completed_w = completed_set.clone();
    let inflight_w = in_flight_remote.clone();
    let hedged_w = hedged_wins.clone();
    let job_done_w = job_done.clone();
    let chunks_done_w = chunks_completed_counter.clone();
    let sockets_w = active_sockets.clone();

    let writer_handle = thread::spawn(move || -> Result<()> {
        let mut written_chunks = 0u64;
        while written_chunks < total_chunks {
            let chunk = match res_rx.recv() {
                Ok(c) => c,
                Err(_) => bail!(
                    "workers stopped before finishing extraction ({}/{})",
                    written_chunks,
                    total_chunks
                ),
            };
            let won = {
                let mut done = completed_w.lock().unwrap();
                done.insert(chunk.chunk_id)
            };
            if !won {
                continue;
            }
            chunks_done_w.fetch_add(1, Ordering::Relaxed);
            {
                let mut inf = inflight_w.lock().unwrap();
                inf.remove(&chunk.chunk_id);
            }
            if chunk.orig_xxh3 != 0 {
                let actual = xxh3_64(&chunk.output);
                if actual != chunk.orig_xxh3 {
                    bail!(
                        "extracted chunk {} integrity check FAILED (expected {:016x}, got {:016x})",
                        chunk.chunk_id,
                        chunk.orig_xxh3,
                        actual
                    );
                }
            }
            if chunk.was_hedged {
                hedged_w.fetch_add(1, Ordering::Relaxed);
            }

            sink.write_slab(chunk.orig_offset, &chunk.output)?;

            let st = &stats_w[chunk.node_idx];
            st.chunks_won.fetch_add(1, Ordering::Relaxed);
            st.orig_bytes.fetch_add(chunk.orig_len as u64, Ordering::Relaxed);
            st.wire_bytes.fetch_add(chunk.wire_bytes, Ordering::Relaxed);
            written_chunks += 1;
        }
        job_done_w.store(true, Ordering::Release);
        shutdown_all_sockets(&sockets_w);
        Ok(())
    });

    for entry in &manifest.entries {
        let is_raw_stored = (entry.chunk_flags & CHUNK_FLAG_RAW_STORED) != 0;
        let budget_size = (entry.comp_len as usize).saturating_add(entry.orig_len as usize);
        let guard = Arc::new(mem_budget.acquire(budget_size));
        let mut comp_buf = vec![0u8; entry.comp_len as usize];
        read_exact_at(&in_file, &mut comp_buf, entry.comp_offset)?;

        if is_raw_stored {
            // Stored raw slab: write straight to sink with zero decompression CPU!
            drop(guard);
            res_tx.send(CompletedChunk {
                chunk_id: entry.chunk_id,
                orig_offset: entry.orig_offset,
                orig_len: entry.orig_len as usize,
                orig_xxh3: entry.xxh3_64,
                chunk_flags: entry.chunk_flags,
                dedup_ref_chunk_id: None,
                output: comp_buf,
                node_idx: local_node_idx,
                was_hedged: false,
                wire_bytes: 0,
            })?;
            continue;
        }

        let task = Arc::new(WorkTask {
            chunk_id: entry.chunk_id,
            orig_offset: entry.orig_offset,
            orig_len: entry.orig_len as usize,
            expected_xxh3: entry.xxh3_64,
            chunk_flags: entry.chunk_flags,
            input: Arc::new(comp_buf),
            _budget: guard,
        });
        work_tx.send(task)?;
    }

    reader_done.store(true, Ordering::Release);
    drop(work_tx);
    drop(res_tx);

    writer_handle.join().unwrap()?;
    let elapsed = start.elapsed().as_secs_f64().max(1e-6);

    job_done.store(true, Ordering::Release);
    shutdown_all_sockets(&active_sockets);
    for h in worker_handles {
        let _ = h.join();
    }

    let mut blake3_hex = None;
    if params.verify && is_single_file_sink {
        if let Some(expected_b3) = manifest.whole_file_blake3 {
            let actual_b3 = hash_file_blake3(params.output_path)?;
            if actual_b3 != expected_b3 {
                bail!(
                    "whole-file BLAKE3 mismatch! expected {}, got {}",
                    hex_encode(&expected_b3),
                    hex_encode(&actual_b3)
                );
            }
            blake3_hex = Some(hex_encode(&actual_b3));
        }
    }

    let throughput_mbps = (total_orig_size as f64 / 1048576.0) / elapsed;
    let ratio = total_orig_size as f64 / comp_bytes.max(1) as f64;

    let summary = JobSummary {
        elapsed_secs: elapsed,
        orig_bytes: total_orig_size,
        comp_bytes,
        chunks: total_chunks,
        block_size: max_block,
        throughput_mbps,
        ratio,
        hedged_wins: hedged_wins.load(Ordering::Relaxed),
        wire_saved_bytes: wire_saved_bytes.load(Ordering::Relaxed),
        dedup_saved_bytes: 0,
        raw_bypass_bytes: 0,
        blake3_hex,
        node_stats: stats_vec.iter().map(|s| s.report()).collect(),
    };

    if !params.quiet {
        print_job_summary(if is_dir_unpack { "UNPACK" } else { "DECOMPRESS" }, &summary);
    }
    Ok(summary)
}

pub fn run_inspect(path: &Path, list_files: bool) -> Result<()> {
    let mut f = File::open(path)?;
    let comp_len = f.metadata()?.len();
    let m = read_manifest(&mut f)?;
    let dedup_chunks = m
        .entries
        .iter()
        .filter(|e| (e.chunk_flags & CHUNK_FLAG_DEDUP_REF) != 0)
        .count();
    let dedup_bytes: u64 = m
        .entries
        .iter()
        .filter(|e| (e.chunk_flags & CHUNK_FLAG_DEDUP_REF) != 0)
        .map(|e| e.orig_len as u64)
        .sum();
    let raw_chunks = m
        .entries
        .iter()
        .filter(|e| (e.chunk_flags & CHUNK_FLAG_RAW_STORED) != 0 && (e.chunk_flags & CHUNK_FLAG_DEDUP_REF) == 0)
        .count();
    let raw_bytes: u64 = m
        .entries
        .iter()
        .filter(|e| (e.chunk_flags & CHUNK_FLAG_RAW_STORED) != 0 && (e.chunk_flags & CHUNK_FLAG_DEDUP_REF) == 0)
        .map(|e| e.orig_len as u64)
        .sum();

    println!("\n=== squiz-archive Inspect: {} ===", path.display());
    println!("  Format          : {:?} | Codec: {}", m.format, m.codec.name());
    println!(
        "  Original Size   : {:.2} MiB ({:.2} GiB)",
        m.total_orig_size as f64 / 1048576.0,
        m.total_orig_size as f64 / 1073741824.0
    );
    println!(
        "  Archive Size    : {:.2} MiB ({:.2} GiB) | Ratio: {:.3}x ({:.1}% saved)",
        comp_len as f64 / 1048576.0,
        comp_len as f64 / 1073741824.0,
        m.total_orig_size as f64 / comp_len.max(1) as f64,
        (1.0 - (comp_len as f64 / m.total_orig_size.max(1) as f64)) * 100.0
    );
    println!(
        "  Chunks          : {} total | {} dedup ({:.2} MiB saved) | {} raw-bypass ({:.2} MiB)",
        m.entries.len(),
        dedup_chunks,
        dedup_bytes as f64 / 1048576.0,
        raw_chunks,
        raw_bytes as f64 / 1048576.0
    );
    if let Some(b3) = m.whole_file_blake3 {
        println!("  BLAKE3 Digest   : {}", hex_encode(&b3));
    }
    if !m.files.is_empty() {
        let regular = m.files.iter().filter(|x| !x.is_dir).count();
        println!("  Packed Entries  : {} files, {} dirs", regular, m.files.len() - regular);
        if list_files {
            println!("\n  {:<12} {}", "SIZE (KiB)", "PATH");
            println!("  {}", "-".repeat(64));
            for entry in m.files.iter().filter(|x| !x.is_dir).take(100) {
                println!("  {:<12.1} {}", entry.size as f64 / 1024.0, entry.rel_path);
            }
            if regular > 100 {
                println!("  ... and {} more files", regular - 100);
            }
        }
    }
    println!();
    Ok(())
}

fn effective_node_threads(node: &ProbedNode, has_remotes: bool) -> usize {
    let max_t = node.caps.max_threads as usize;
    if node.spec.is_local
        && has_remotes
        && matches!(node.spec.threads, crate::resource::ThreadAlloc::Auto)
    {
        if max_t >= 8 {
            return max_t - 2;
        } else if max_t >= 4 {
            return max_t - 1;
        }
    }
    node.spec.threads.resolve(max_t)
}

fn shutdown_all_sockets(sockets: &Arc<Mutex<Vec<TcpStream>>>) {
    let guard = sockets.lock().unwrap();
    for s in guard.iter() {
        let _ = s.shutdown(Shutdown::Both);
    }
}

fn select_active_nodes(
    nodes: &[ProbedNode],
    schedule: ScheduleMode,
    codec: CodecId,
    is_decompress: bool,
) -> Result<Vec<ProbedNode>> {
    let enabled: Vec<ProbedNode> = nodes
        .iter()
        .filter(|n| n.spec.enabled && n.reachable)
        .cloned()
        .collect();
    if enabled.is_empty() {
        bail!("no reachable enabled nodes available");
    }

    match schedule {
        ScheduleMode::LocalOnly => {
            let locals: Vec<ProbedNode> = enabled.into_iter().filter(|n| n.spec.is_local).collect();
            if locals.is_empty() {
                bail!("--schedule local-only requested, but local node is disabled");
            }
            Ok(locals)
        }
        ScheduleMode::ForceAll => Ok(enabled),
        ScheduleMode::Auto => {
            let local_threads: usize = enabled
                .iter()
                .filter(|n| n.spec.is_local)
                .map(|n| n.spec.threads.resolve(n.caps.max_threads as usize))
                .sum();
            if local_threads == 0 {
                return Ok(enabled);
            }
            if is_decompress {
                let per_thread_mbps = match codec {
                    CodecId::Raw => 2000.0,
                    CodecId::Zstd => 220.0,
                    CodecId::Lz4 => 650.0,
                    CodecId::Lzma2 => 65.0,
                };
                let local_est_mbps = local_threads as f64 * per_thread_mbps;
                let mut filtered = Vec::new();
                for n in enabled {
                    if n.spec.is_local || (n.probe_bw_mbps * 3.0) >= (local_est_mbps * 0.25) {
                        filtered.push(n);
                    }
                }
                return Ok(filtered);
            }
            if codec == CodecId::Lz4 {
                let mut filtered = Vec::new();
                for n in enabled {
                    if n.spec.is_local || n.probe_bw_mbps >= 400.0 {
                        filtered.push(n);
                    }
                }
                return Ok(filtered);
            }
            Ok(enabled)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_local_workers(
    node_idx: usize,
    threads: usize,
    codec: CodecId,
    level: i32,
    is_decompress: bool,
    hedge: bool,
    work_rx: crossbeam_channel::Receiver<Arc<WorkTask>>,
    res_tx: crossbeam_channel::Sender<CompletedChunk>,
    reader_done: Arc<AtomicBool>,
    job_done: Arc<AtomicBool>,
    completed_set: Arc<Mutex<HashSet<u64>>>,
    in_flight_remote: Arc<Mutex<HashMap<u64, InFlightEntry>>>,
    local_pace: Arc<LocalPace>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let work_rx_c = work_rx.clone();
            let res_tx_c = res_tx.clone();
            let reader_done_c = reader_done.clone();
            let job_done_c = job_done.clone();
            let completed_c = completed_set.clone();
            let inflight_c = in_flight_remote.clone();
            let pace_c = local_pace.clone();

            handles.push(thread::spawn(move || {
                loop {
                    if job_done_c.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut was_hedged = false;
                    let task_opt = match work_rx_c.try_recv() {
                        Ok(t) => Some(t),
                        Err(_) => {
                            if hedge && reader_done_c.load(Ordering::Acquire) {
                                let mut inf = inflight_c.lock().unwrap();
                                let candidate_id = inf
                                    .iter()
                                    .filter(|(_, e)| !e.hedged)
                                    .min_by_key(|(_, e)| e.dispatched_at)
                                    .map(|(&id, _)| id);
                                if let Some(cid) = candidate_id {
                                    if let Some(entry) = inf.get_mut(&cid) {
                                        entry.hedged = true;
                                        was_hedged = true;
                                        Some(entry.task.clone())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    };

                    let task = match task_opt {
                        Some(t) => t,
                        None => match work_rx_c.recv_timeout(Duration::from_millis(5)) {
                            Ok(t) => t,
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => {
                                if job_done_c.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(3));
                                continue;
                            }
                        },
                    };

                    if completed_c.lock().unwrap().contains(&task.chunk_id) {
                        continue;
                    }

                    let t0 = Instant::now();
                    let out = if is_decompress {
                        decompress_block(codec, &task.input, task.orig_len)
                    } else {
                        compress_block(codec, level, &task.input)
                    };
                    pace_c.record(t0.elapsed().as_micros() as u64);

                    match out {
                        Ok(output) => {
                            let _ = res_tx_c.send(CompletedChunk {
                                chunk_id: task.chunk_id,
                                orig_offset: task.orig_offset,
                                orig_len: task.orig_len,
                                orig_xxh3: task.expected_xxh3,
                                chunk_flags: task.chunk_flags,
                                dedup_ref_chunk_id: None,
                                output,
                                node_idx,
                                was_hedged,
                                wire_bytes: 0,
                            });
                        }
                        Err(e) => {
                            eprintln!("[local] chunk {} error: {:#}", task.chunk_id, e);
                            break;
                        }
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_remote_worker_node(
    node_idx: usize,
    spec: NodeSpec,
    eff_threads: usize,
    eff_mem_mb: u32,
    block_size: usize,
    total_chunks: u64,
    has_local: bool,
    airtime_weight: f64,
    codec: CodecId,
    level: i32,
    is_decompress: bool,
    wire_codec: WireCodec,
    security: SecurityMode,
    token: String,
    work_tx: crossbeam_channel::Sender<Arc<WorkTask>>,
    work_rx: crossbeam_channel::Receiver<Arc<WorkTask>>,
    res_tx: crossbeam_channel::Sender<CompletedChunk>,
    job_done: Arc<AtomicBool>,
    completed_set: Arc<Mutex<HashSet<u64>>>,
    in_flight_remote: Arc<Mutex<HashMap<u64, InFlightEntry>>>,
    chunks_completed_counter: Arc<AtomicU64>,
    local_pace: Arc<LocalPace>,
    wire_saved_bytes: Arc<AtomicU64>,
    active_sockets: Arc<Mutex<Vec<TcpStream>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let num_streams = spec.streams.clamp(1, 8);
        let mem_credits = ((eff_mem_mb as usize) * 1024 * 1024) / (block_size.max(64 * 1024) * 2);
        let raw_max = ((eff_threads * 3) / 2)
            .max(eff_threads + 2)
            .min(mem_credits.max(2))
            .clamp(2, 48);
        // Airtime-Weighted Credit Ceiling (v6): scale ceiling by peer's airtime efficiency!
        let max_credits = ((raw_max as f64 * airtime_weight).round() as usize).clamp(2, raw_max);
        let init_credits = ((eff_threads / 3) as f64 * airtime_weight)
            .round()
            .clamp(2.0, 12.0) as usize;
        let credit_gate = AdaptiveCreditGate::new(init_credits.min(max_credits), 2, max_credits);

        let mut stream_handles = Vec::with_capacity(num_streams);
        let bw_per_stream = spec.bw_limit_bps.map(|b| (b / num_streams).max(65536));

        for sid in 0..num_streams {
            let target = spec.target.clone();
            let tok = token.clone();
            let work_tx_c = work_tx.clone();
            let work_rx_c = work_rx.clone();
            let res_tx_c = res_tx.clone();
            let job_done_c = job_done.clone();
            let completed_c = completed_set.clone();
            let inflight_c = in_flight_remote.clone();
            let credits_c = credit_gate.clone();
            let chunks_done_c = chunks_completed_counter.clone();
            let pace_c = local_pace.clone();
            let saved_c = wire_saved_bytes.clone();
            let sockets_c = active_sockets.clone();

            stream_handles.push(thread::spawn(move || {
                // Roaming-Safe reconnect loop (up to 3 transparent reconnects on brief Wi-Fi roam/fade!)
                for attempt in 0..3u32 {
                    if job_done_c.load(Ordering::Relaxed) {
                        break;
                    }
                    if attempt > 0 {
                        thread::sleep(Duration::from_millis(250 * attempt as u64));
                    }

                    let mut stream = match TcpStream::connect(&target) {
                        Ok(s) => s,
                        Err(e) => {
                            if attempt == 2 {
                                eprintln!("[remote {}#{}] connect failed: {}", target, sid, e);
                            }
                            continue;
                        }
                    };
                    if tune_tcp_stream(&stream).is_err() {
                        continue;
                    }
                    let (cipher, _caps) = match client_handshake(
                        &mut stream,
                        &tok,
                        security,
                        sid as u16,
                        eff_threads as u16,
                        eff_mem_mb,
                    ) {
                        Ok(x) => x,
                        Err(e) => {
                            eprintln!("[remote {}#{}] handshake failed: {:#}", target, sid, e);
                            return; // Do not retry auth failures!
                        }
                    };

                    // Roaming-Safe 20s stall timeouts (prevents hanging forever on BSSID roam/fade!)
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));

                    if let Ok(dup) = stream.try_clone() {
                        sockets_c.lock().unwrap().push(dup);
                    }

                    let rx_stream = match stream.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let mut rx_cipher = cipher.clone();
                    let mut tx_cipher = cipher;

                    let stream_pending: Arc<Mutex<HashMap<u64, (Arc<WorkTask>, Instant, u64)>>> =
                        Arc::new(Mutex::new(HashMap::new()));
                    let stream_pending_rx = stream_pending.clone();
                    let stream_closed = Arc::new(AtomicBool::new(false));
                    let stream_closed_rx = stream_closed.clone();
                    let stream_failed = Arc::new(AtomicBool::new(false));
                    let stream_failed_rx = stream_failed.clone();
                    let credits_rx = credits_c.clone();
                    let res_tx_rx = res_tx_c.clone();
                    let job_done_rx = job_done_c.clone();
                    let work_tx_rx = work_tx_c.clone();
                    let completed_rx = completed_c.clone();
                    let saved_rx = saved_c.clone();
                    let target_rx = target.clone();

                    let rx_handle = thread::spawn(move || {
                        let mut rx_reader = BufReader::with_capacity(256 * 1024, rx_stream);
                        let mut rx_buf = Vec::with_capacity(block_size.min(8 * 1024 * 1024));
                        let max_frame = (block_size * 2 + 1024 * 1024).max(DEFAULT_MAX_FRAME_BYTES);
                        loop {
                            let hdr = match rx_cipher.read_frame_into(&mut rx_reader, &mut rx_buf, max_frame) {
                                Ok(h) => {
                                    arm_quickack(rx_reader.get_ref());
                                    h
                                }
                                Err(e) => {
                                    // If socket merely hit read timeout while NO chunks are in flight (e.g. disk busy opening tiny files),
                                    // stay connected instead of falsely triggering roam recovery!
                                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                        if matches!(
                                            io_err.kind(),
                                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                        ) && stream_pending_rx.lock().unwrap().is_empty()
                                            && !job_done_rx.load(Ordering::Relaxed)
                                            && !stream_closed_rx.load(Ordering::Relaxed)
                                        {
                                            continue;
                                        }
                                    }
                                    if !job_done_rx.load(Ordering::Relaxed)
                                        && !stream_closed_rx.load(Ordering::Relaxed)
                                    {
                                        stream_failed_rx.store(true, Ordering::Release);
                                        eprintln!(
                                            "[remote {}#{}] roam/stall recovery triggered: {:#}",
                                            target_rx, sid, e
                                        );
                                    }
                                    break;
                                }
                            };
                            let entry = stream_pending_rx.lock().unwrap().remove(&hdr.chunk_id);
                            match hdr.msg_type {
                                MsgType::JobResp => {
                                    if let Some((task, sent_at, tx_wire)) = entry {
                                        let total_rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
                                        let worker_compute_ms = hdr.orig_len as f64 / 1000.0;
                                        let pure_net_ms = (total_rtt_ms - worker_compute_ms).max(1.0);
                                        credits_rx.complete_with_timing(
                                            pure_net_ms,
                                            total_rtt_ms,
                                            task.orig_len,
                                        );
                                        let rx_wire = rx_buf.len() as u64;
                                        let expanded_res: Result<Vec<u8>> =
                                            if (hdr.flags & FLAG_WIRE_ZSTD1) != 0 {
                                                wire_expand_zstd1(&rx_buf, task.orig_len)
                                            } else if (hdr.flags & FLAG_WIRE_LZ4) != 0 {
                                                lz4_flex::block::decompress_size_prepended(&rx_buf)
                                                    .map_err(|e| anyhow::anyhow!("lz4: {}", e))
                                            } else {
                                                Ok(std::mem::take(&mut rx_buf))
                                            };

                                        match expanded_res {
                                            Ok(output) => {
                                                if output.len() as u64 > rx_wire
                                                    && (hdr.flags & (FLAG_WIRE_LZ4 | FLAG_WIRE_ZSTD1)) != 0
                                                {
                                                    saved_rx.fetch_add(
                                                        output.len() as u64 - rx_wire,
                                                        Ordering::Relaxed,
                                                    );
                                                }
                                                let _ = res_tx_rx.send(CompletedChunk {
                                                    chunk_id: task.chunk_id,
                                                    orig_offset: task.orig_offset,
                                                    orig_len: task.orig_len,
                                                    orig_xxh3: task.expected_xxh3,
                                                    chunk_flags: task.chunk_flags,
                                                    dedup_ref_chunk_id: None,
                                                    output,
                                                    node_idx,
                                                    was_hedged: false,
                                                    wire_bytes: tx_wire + rx_wire,
                                                });
                                            }
                                            Err(e) => {
                                                eprintln!("[remote {}#{}] rx expand err: {:#}", target_rx, sid, e);
                                                let _ = work_tx_rx.send(task);
                                            }
                                        }
                                    } else {
                                        credits_rx.release_only();
                                    }
                                }
                                MsgType::Error => {
                                    credits_rx.release_only();
                                    if let Some((task, _, _)) = entry {
                                        let _ = work_tx_rx.send(task);
                                    }
                                }
                                _ => {
                                    credits_rx.release_only();
                                }
                            }
                        }

                        // Roaming-Safe Idempotent Slab Re-Queue: immediately return all unfinished slabs!
                        let orphans: Vec<Arc<WorkTask>> = {
                            let mut guard = stream_pending_rx.lock().unwrap();
                            guard.drain().map(|(_, (t, _, _))| t).collect()
                        };
                        let orphan_cnt = orphans.len();
                        for _ in 0..orphan_cnt {
                            credits_rx.release_only();
                        }
                        if !orphans.is_empty() && !job_done_rx.load(Ordering::Relaxed) {
                            let done = completed_rx.lock().unwrap();
                            for t in orphans {
                                if !done.contains(&t.chunk_id) {
                                    let _ = work_tx_rx.send(t);
                                }
                            }
                        }
                    });

                    let mut pacer = bw_per_stream.map(BandwidthPacer::new);
                    let mut tx_scratch = Vec::with_capacity(block_size);

                    while !job_done_c.load(Ordering::Relaxed) && !stream_failed.load(Ordering::Acquire) {
                        if !credits_c.acquire(&job_done_c) {
                            break;
                        }

                        if has_local {
                            let done = chunks_done_c.load(Ordering::Relaxed);
                            let remaining = total_chunks.saturating_sub(done);
                            let tail_window = (pace_c.threads * 2).max(8) as u64;
                            if remaining > 0 && remaining <= tail_window {
                                let (rem_total_ms, rem_samples) = credits_c.ema_total_and_samples();
                                if rem_samples >= 3 {
                                    if let Some(local_eta_ms) = pace_c.drain_eta_ms(remaining) {
                                        if local_eta_ms < rem_total_ms * 0.85 {
                                            credits_c.release_only();
                                            thread::sleep(Duration::from_millis(10));
                                            continue;
                                        }
                                    }
                                }
                            }
                        }

                        let task = match work_rx_c.recv_timeout(Duration::from_millis(15)) {
                            Ok(t) => t,
                            Err(RecvTimeoutError::Timeout) => {
                                credits_c.release_only();
                                continue;
                            }
                            Err(RecvTimeoutError::Disconnected) => {
                                credits_c.release_only();
                                break;
                            }
                        };

                        if completed_c.lock().unwrap().contains(&task.chunk_id) {
                            credits_c.release_only();
                            continue;
                        }

                        // v6 Wi-Fi-Native Adaptive Wire Pre-Shrink (zstd L1 on Wi-Fi, LZ4 on wired GbE+)
                        let mut flags = if is_decompress {
                            let mut f = FLAG_DECOMPRESS;
                            match wire_codec {
                                WireCodec::Zstd1 => f |= FLAG_ALLOW_RESP_ZSTD1,
                                WireCodec::Lz4 => f |= FLAG_ALLOW_RESP_LZ4,
                                _ => {}
                            }
                            f
                        } else {
                            0
                        };

                        let tx_wire_bytes: usize;
                        let payload_ready_in_scratch: bool;

                        if !is_decompress && task.input.len() >= 16384 && wire_codec != WireCodec::None {
                            let shrunk_opt = match wire_codec {
                                WireCodec::Zstd1 | WireCodec::Auto => {
                                    wire_shrink_zstd1(&task.input).ok().map(|v| (v, FLAG_WIRE_ZSTD1))
                                }
                                WireCodec::Lz4 => {
                                    Some((lz4_flex::block::compress_prepend_size(&task.input), FLAG_WIRE_LZ4))
                                }
                                WireCodec::None => None,
                            };
                            if let Some((shrunk, wflag)) = shrunk_opt {
                                if shrunk.len() * 100 < task.input.len() * 95 {
                                    saved_c.fetch_add(
                                        (task.input.len() - shrunk.len()) as u64,
                                        Ordering::Relaxed,
                                    );
                                    flags |= wflag;
                                    tx_wire_bytes = shrunk.len();
                                    tx_scratch = shrunk;
                                    payload_ready_in_scratch = true;
                                } else {
                                    tx_wire_bytes = task.input.len();
                                    payload_ready_in_scratch = false;
                                }
                            } else {
                                tx_wire_bytes = task.input.len();
                                payload_ready_in_scratch = false;
                            }
                        } else {
                            tx_wire_bytes = task.input.len();
                            payload_ready_in_scratch = false;
                        }

                        let now = Instant::now();
                        {
                            let mut inf = inflight_c.lock().unwrap();
                            inf.insert(
                                task.chunk_id,
                                InFlightEntry {
                                    task: task.clone(),
                                    dispatched_at: now,
                                    hedged: false,
                                },
                            );
                        }
                        stream_pending.lock().unwrap().insert(
                            task.chunk_id,
                            (task.clone(), now, tx_wire_bytes as u64),
                        );

                        let hdr = FrameHeader {
                            msg_type: MsgType::JobReq,
                            codec: codec as u8,
                            level: level as i8,
                            flags,
                            chunk_id: task.chunk_id,
                            orig_len: task.orig_len as u32,
                            payload_len: tx_wire_bytes as u32,
                            xxh3: if !is_decompress && !payload_ready_in_scratch {
                                task.expected_xxh3
                            } else {
                                0
                            },
                        };

                        if let Some(ref mut p) = pacer {
                            p.pace(tx_wire_bytes);
                        }

                        let write_res = if payload_ready_in_scratch {
                            tx_cipher.write_frame(&mut stream, hdr, &mut tx_scratch)
                        } else {
                            tx_cipher.write_frame_slice(&mut stream, hdr, &task.input)
                        };

                        if let Err(e) = write_res {
                            if !job_done_c.load(Ordering::Relaxed) {
                                stream_failed.store(true, Ordering::Release);
                                eprintln!("[remote {}#{}] tx error (re-queueing slab): {}", target, sid, e);
                            }
                            stream_pending.lock().unwrap().remove(&task.chunk_id);
                            credits_c.release_only();
                            if !job_done_c.load(Ordering::Relaxed) {
                                let _ = work_tx_c.send(task);
                            }
                            break;
                        }
                    }

                    while !stream_pending.lock().unwrap().is_empty()
                        && !job_done_c.load(Ordering::Relaxed)
                        && !stream_failed.load(Ordering::Acquire)
                    {
                        thread::sleep(Duration::from_millis(5));
                    }

                    stream_closed.store(true, Ordering::Release);
                    if !job_done_c.load(Ordering::Relaxed) && !stream_failed.load(Ordering::Acquire) {
                        let _ = tx_cipher.write_frame(
                            &mut stream,
                            FrameHeader {
                                msg_type: MsgType::Shutdown,
                                codec: 0,
                                level: 0,
                                flags: 0,
                                chunk_id: 0,
                                orig_len: 0,
                                payload_len: 0,
                                xxh3: 0,
                            },
                            &mut [],
                        );
                    }
                    let _ = stream.shutdown(Shutdown::Both);
                    let _ = rx_handle.join();

                    if !stream_failed.load(Ordering::Acquire) || job_done_c.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }));
        }

        for h in stream_handles {
            let _ = h.join();
        }
    })
}

pub fn run_net_bench(
    specs: &[NodeSpec],
    token: &str,
    security: SecurityMode,
    total_mib: usize,
    streams: usize,
) -> Result<()> {
    let streams = streams.clamp(1, 8);
    let chunk_bytes = 1024 * 1024usize;
    let frames_per_stream = (total_mib / streams).max(4);
    let actual_total_mib = frames_per_stream * streams * 2;

    println!(
        "\n=== squiz-archive Network Layer Benchmark (sec={:?}, streams={}, {} MiB bidirectional/node) ===",
        security, streams, actual_total_mib
    );

    for spec in specs {
        if spec.is_local {
            continue;
        }
        let target = spec.target.clone();
        let start = Instant::now();
        let mut handles = Vec::with_capacity(streams);
        for sid in 0..streams {
            let t = target.clone();
            let tok = token.to_string();
            handles.push(thread::spawn(move || -> Result<u64> {
                let mut stream = TcpStream::connect(&t)?;
                tune_tcp_stream(&stream)?;
                let (mut cipher, _caps) = client_handshake(&mut stream, &tok, security, sid as u16, 0, 0)?;
                let mut rx_stream = BufReader::with_capacity(256 * 1024, stream.try_clone()?);
                let mut rx_cipher = cipher.clone();

                let rx_h = thread::spawn(move || -> Result<u64> {
                    let mut buf = Vec::with_capacity(chunk_bytes);
                    let mut got = 0u64;
                    for _ in 0..frames_per_stream {
                        let hdr = rx_cipher.read_frame_into(&mut rx_stream, &mut buf, 8 * 1024 * 1024)?;
                        arm_quickack(rx_stream.get_ref());
                        if hdr.msg_type == MsgType::ProbeResp {
                            got += buf.len() as u64;
                        }
                    }
                    Ok(got)
                });

                let payload = vec![0x5Au8; chunk_bytes];
                let mut sent = 0u64;
                for i in 0..frames_per_stream {
                    cipher.write_frame_slice(
                        &mut stream,
                        FrameHeader {
                            msg_type: MsgType::ProbeReq,
                            codec: 0,
                            level: 0,
                            flags: 0,
                            chunk_id: i as u64,
                            orig_len: chunk_bytes as u32,
                            payload_len: chunk_bytes as u32,
                            xxh3: 0,
                        },
                        &payload,
                    )?;
                    sent += chunk_bytes as u64;
                }
                let rx_bytes = rx_h.join().unwrap()?;
                let _ = cipher.write_frame(
                    &mut stream,
                    FrameHeader {
                        msg_type: MsgType::Shutdown,
                        codec: 0,
                        level: 0,
                        flags: 0,
                        chunk_id: 0,
                        orig_len: 0,
                        payload_len: 0,
                        xxh3: 0,
                    },
                    &mut [],
                );
                Ok(sent + rx_bytes)
            }));
        }

        let mut total_bytes = 0u64;
        for h in handles {
            total_bytes += h.join().unwrap()?;
        }
        let secs = start.elapsed().as_secs_f64().max(1e-6);
        let mibs = (total_bytes as f64 / 1048576.0) / secs;
        let mbps = (total_bytes as f64 * 8.0 / 1_000_000.0) / secs;
        println!(
            "  {:<24} : {:6.2} MiB/s ({:6.1} Mbps) bidirectional | {:.2} MiB in {:.3} s",
            target,
            mibs,
            mbps,
            total_bytes as f64 / 1048576.0,
            secs
        );
    }
    println!();
    Ok(())
}

pub fn hash_file_blake3(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update_rayon(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

pub fn print_job_summary(op: &str, s: &JobSummary) {
    println!("\n================ squiz-archive {} SUMMARY ================", op);
    println!(
        "  Wall Time   : {:.3} s | Throughput: {:.2} MiB/s (orig) | Ratio: {:.3}x ({:.2} -> {:.2} MiB)",
        s.elapsed_secs,
        s.throughput_mbps,
        s.ratio,
        s.orig_bytes as f64 / 1048576.0,
        s.comp_bytes as f64 / 1048576.0,
    );
    println!(
        "  Chunks      : {} x {:.2} MiB | Hedged: {} | Wire Saved: {:.2} MiB | Dedup: {:.2} MiB | Raw Skip: {:.2} MiB",
        s.chunks,
        s.block_size as f64 / 1048576.0,
        s.hedged_wins,
        s.wire_saved_bytes as f64 / 1048576.0,
        s.dedup_saved_bytes as f64 / 1048576.0,
        s.raw_bypass_bytes as f64 / 1048576.0
    );
    if let Some(ref h) = s.blake3_hex {
        println!("  BLAKE3      : {}", h);
    }
    println!(
        "  {:<34} {:>7} {:>8} {:>11} {:>9} {:>10}",
        "NODE", "THREADS", "CHUNKS", "ORIG MiB", "SHARE", "WIRE MiB"
    );
    println!("  {}", "-".repeat(84));
    for n in &s.node_stats {
        let share = if s.orig_bytes > 0 {
            (n.orig_bytes as f64 * 100.0) / s.orig_bytes as f64
        } else {
            0.0
        };
        println!(
            "  {:<34} {:>7} {:>8} {:>11.2} {:>8.1}% {:>10.2}",
            n.name,
            n.threads,
            n.chunks_won,
            n.orig_bytes as f64 / 1048576.0,
            share,
            n.wire_bytes as f64 / 1048576.0
        );
    }
    println!("============================================================\n");
}
