use crate::codec::{
    CodecId, compress_block, decompress_block, wire_expand_zstd1, wire_shrink_zstd1,
};
use crate::pool::ByteBudget;
use crate::protocol::{
    DEFAULT_MAX_FRAME_BYTES, FLAG_ALLOW_RESP_LZ4, FLAG_ALLOW_RESP_ZSTD1, FLAG_DECOMPRESS,
    FLAG_WIRE_LZ4, FLAG_WIRE_ZSTD1, FrameHeader, MsgType, arm_quickack, server_handshake,
    tune_tcp_listener, tune_tcp_stream,
};
use crate::resource::local_worker_caps;
use anyhow::{Context, Result};
use crossbeam_channel::bounded;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;
use xxhash_rust::xxh3::xxh3_64;

#[derive(Clone)]
pub struct WorkerConfig {
    pub bind_addr: SocketAddr,
    pub token: String,
    pub max_threads: usize,
    pub max_mem_bytes: usize,
    pub max_frame_bytes: usize,
    pub allow_auth_only: bool,
}

#[derive(Clone)]
struct SlotSemaphore {
    inner: Arc<(Mutex<usize>, Condvar, usize)>,
}

impl SlotSemaphore {
    fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new((Mutex::new(0), Condvar::new(), limit.max(1))),
        }
    }

    fn acquire(&self) -> SlotGuard {
        let (lock, cvar, limit) = &*self.inner;
        let mut active = lock.lock().unwrap();
        while *active >= *limit {
            active = cvar.wait(active).unwrap();
        }
        *active += 1;
        SlotGuard { sem: self.clone() }
    }
}

struct SlotGuard {
    sem: SlotSemaphore,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let (lock, cvar, _) = &*self.sem.inner;
        let mut active = lock.lock().unwrap();
        *active = active.saturating_sub(1);
        cvar.notify_one();
    }
}

pub fn run_worker(cfg: WorkerConfig) -> Result<()> {
    let caps = local_worker_caps(Some(cfg.max_threads), Some(cfg.max_mem_bytes));
    let hard_threads = caps.max_threads as usize;
    let hard_mem_bytes = (caps.max_mem_mb as usize) * 1024 * 1024;

    let pool = Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(hard_threads)
            .thread_name(|i| format!("sqz-wrk-{}", i))
            .build()
            .context("failed to build worker rayon thread pool")?,
    );
    let mem_budget = ByteBudget::new(hard_mem_bytes);

    let domain = match cfg.bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    tune_tcp_listener(&sock)?;
    sock.bind(&cfg.bind_addr.into())
        .with_context(|| format!("failed to bind worker on {}", cfg.bind_addr))?;
    sock.listen(128)?;
    let listener: TcpListener = sock.into();

    println!(
        "[squiz-archive worker] Listening on {} | host={} ({}) | CPU={} | ceiling: {}T / {} MiB | security={}",
        cfg.bind_addr,
        caps.hostname,
        caps.os_arch,
        caps.cpu_brand,
        hard_threads,
        caps.max_mem_mb,
        if cfg.allow_auth_only {
            "AEAD + auth-only allowed"
        } else {
            "AEAD required"
        }
    );

    let cfg = Arc::new(cfg);
    let caps = Arc::new(caps);

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[worker] accept error: {}", e);
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let cfg_c = cfg.clone();
        let caps_c = caps.clone();
        let pool_c = pool.clone();
        let mem_c = mem_budget.clone();

        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, &peer, &cfg_c, &caps_c, pool_c, mem_c) {
                eprintln!("[worker] peer {} ended: {:#}", peer, e);
            }
        });
    }

    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    peer: &str,
    cfg: &WorkerConfig,
    caps: &crate::protocol::WorkerCaps,
    pool: Arc<rayon::ThreadPool>,
    mem_budget: ByteBudget,
) -> Result<()> {
    tune_tcp_stream(&stream)?;
    let (cipher, req_threads, _req_mem_mb, stream_id) =
        server_handshake(&mut stream, &cfg.token, cfg.allow_auth_only, caps)?;

    let eff_slots = if req_threads == 0 {
        caps.max_threads as usize
    } else {
        (req_threads as usize).clamp(1, caps.max_threads as usize)
    };
    let slot_sem = SlotSemaphore::new(eff_slots);

    let mut tx_stream = stream.try_clone()?;
    let mut tx_cipher = cipher.clone();
    let mut rx_cipher = cipher;

    let (resp_tx, resp_rx) = bounded::<(FrameHeader, Vec<u8>)>(eff_slots * 2 + 8);

    let tx_handle = thread::spawn(move || -> Result<()> {
        for (hdr, mut payload) in resp_rx {
            tx_cipher.write_frame(&mut tx_stream, hdr, &mut payload)?;
        }
        Ok(())
    });

    let max_frame = cfg.max_frame_bytes.max(DEFAULT_MAX_FRAME_BYTES);
    let mut rx_reader = BufReader::with_capacity(256 * 1024, stream);
    let mut rx_buf = Vec::with_capacity(4 * 1024 * 1024);

    loop {
        let hdr = match rx_cipher.read_frame_into(&mut rx_reader, &mut rx_buf, max_frame) {
            Ok(h) => {
                arm_quickack(rx_reader.get_ref());
                h
            }
            Err(e) => {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                        || io_err.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        break;
                    }
                }
                eprintln!("[worker] stream {} ({}) rx error: {:#}", stream_id, peer, e);
                break;
            }
        };

        match hdr.msg_type {
            MsgType::Shutdown => break,
            MsgType::ProbeReq => {
                let echo = rx_buf.clone();
                let resp_hdr = FrameHeader {
                    msg_type: MsgType::ProbeResp,
                    codec: 0,
                    level: 0,
                    flags: 0,
                    chunk_id: hdr.chunk_id,
                    orig_len: echo.len() as u32,
                    payload_len: echo.len() as u32,
                    xxh3: xxh3_64(&echo),
                };
                if resp_tx.send((resp_hdr, echo)).is_err() {
                    break;
                }
            }
            MsgType::JobReq => {
                let payload = std::mem::take(&mut rx_buf);
                let budget_bytes = payload.len().saturating_add(hdr.orig_len as usize).max(4096);
                let mem_guard = mem_budget.acquire(budget_bytes);
                let slot_guard = slot_sem.acquire();
                let resp_tx_c = resp_tx.clone();

                pool.spawn(move || {
                    let _mem_guard = mem_guard;
                    let _slot_guard = slot_guard;

                    let is_decompress = (hdr.flags & FLAG_DECOMPRESS) != 0;
                    let wire_lz4 = (hdr.flags & FLAG_WIRE_LZ4) != 0;
                    let wire_zstd1 = (hdr.flags & FLAG_WIRE_ZSTD1) != 0;
                    let allow_resp_lz4 = (hdr.flags & FLAG_ALLOW_RESP_LZ4) != 0;
                    let allow_resp_zstd1 = (hdr.flags & FLAG_ALLOW_RESP_ZSTD1) != 0;

                    let raw_input_res: Result<Vec<u8>> = if wire_zstd1 {
                        wire_expand_zstd1(&payload, hdr.orig_len as usize)
                    } else if wire_lz4 {
                        lz4_flex::block::decompress_size_prepended(&payload)
                            .map_err(|e| anyhow::anyhow!("wire lz4 expand failed: {}", e))
                    } else {
                        Ok(payload)
                    };

                    let compute_t0 = Instant::now();
                    let res = raw_input_res.and_then(|input_data| {
                        CodecId::from_u8(hdr.codec).and_then(|codec| {
                            if is_decompress {
                                decompress_block(codec, &input_data, hdr.orig_len as usize)
                            } else {
                                compress_block(codec, hdr.level as i32, &input_data)
                            }
                        })
                    });
                    let compute_us = compute_t0.elapsed().as_micros().min(u32::MAX as u128) as u32;

                    match res {
                        Ok(mut out) => {
                            let mut resp_flags = if is_decompress { FLAG_DECOMPRESS } else { 0 };
                            if is_decompress && out.len() >= 16384 {
                                if allow_resp_zstd1 {
                                    if let Ok(shrunk) = wire_shrink_zstd1(&out) {
                                        if shrunk.len() * 100 < out.len() * 94 {
                                            out = shrunk;
                                            resp_flags |= FLAG_WIRE_ZSTD1;
                                        }
                                    }
                                } else if allow_resp_lz4 {
                                    let shrunk = lz4_flex::block::compress_prepend_size(&out);
                                    if shrunk.len() * 100 < out.len() * 94 {
                                        out = shrunk;
                                        resp_flags |= FLAG_WIRE_LZ4;
                                    }
                                }
                            }
                            let digest = xxh3_64(&out);
                            let resp_hdr = FrameHeader {
                                msg_type: MsgType::JobResp,
                                codec: hdr.codec,
                                level: hdr.level,
                                flags: resp_flags,
                                chunk_id: hdr.chunk_id,
                                orig_len: compute_us,
                                payload_len: out.len() as u32,
                                xxh3: digest,
                            };
                            let _ = resp_tx_c.send((resp_hdr, out));
                        }
                        Err(e) => {
                            let err_bytes = format!("{}", e).into_bytes();
                            let resp_hdr = FrameHeader {
                                msg_type: MsgType::Error,
                                codec: hdr.codec,
                                level: hdr.level,
                                flags: 0,
                                chunk_id: hdr.chunk_id,
                                orig_len: 0,
                                payload_len: err_bytes.len() as u32,
                                xxh3: 0,
                            };
                            let _ = resp_tx_c.send((resp_hdr, err_bytes));
                        }
                    }
                });
            }
            other => {
                eprintln!("[worker] unexpected msg {:?} from {}", other, peer);
                break;
            }
        }
    }

    drop(resp_tx);
    let _ = tx_handle.join();
    Ok(())
}
