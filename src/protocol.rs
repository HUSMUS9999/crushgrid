use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use anyhow::{Context, Result, bail};
use rand::RngCore;
use socket2::{Socket, TcpKeepalive};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use xxhash_rust::xxh3::xxh3_64;

pub const FRAME_MAGIC: [u8; 4] = *b"HSQ1";
pub const HEADER_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;
pub const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024; // 64 MiB hard cap

pub const FLAG_AEAD: u8 = 0x01;
pub const FLAG_DECOMPRESS: u8 = 0x02;
pub const FLAG_WIRE_LZ4: u8 = 0x04;
pub const FLAG_ALLOW_RESP_LZ4: u8 = 0x08;
pub const FLAG_WIRE_ZSTD1: u8 = 0x10;
pub const FLAG_ALLOW_RESP_ZSTD1: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCodec {
    /// Automatic transport-aware selection: zstd L1 on Wi-Fi/WAN (<100 MiB/s), lz4 on fast Ethernet (>=100 MiB/s)
    Auto,
    /// Force Zstd Level 1 wire-pre-shrink (25-35% smaller than LZ4 on Wi-Fi)
    Zstd1,
    /// Force LZ4 wire-pre-shrink (3500+ MiB/s for 10GbE+)
    Lz4,
    /// Disable wire-pre-shrink
    None,
}

impl WireCodec {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "zstd1" | "zstd" => Ok(Self::Zstd1),
            "lz4" => Ok(Self::Lz4),
            "none" | "off" => Ok(Self::None),
            _ => bail!("invalid --wire-codec '{}': use auto, zstd1, lz4, or none", s),
        }
    }

    pub fn resolve(self, probe_bw_mbps: f64) -> Self {
        match self {
            Self::Auto => {
                if probe_bw_mbps >= 100.0 {
                    Self::Lz4
                } else {
                    Self::Zstd1
                }
            }
            other => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    HelloClient = 1,
    HelloServer = 2,
    AuthClient = 3,
    AuthOk = 4,
    Capabilities = 5,
    ProbeReq = 6,
    ProbeResp = 7,
    JobReq = 8,
    JobResp = 9,
    Error = 10,
    Shutdown = 11,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::HelloClient),
            2 => Ok(Self::HelloServer),
            3 => Ok(Self::AuthClient),
            4 => Ok(Self::AuthOk),
            5 => Ok(Self::Capabilities),
            6 => Ok(Self::ProbeReq),
            7 => Ok(Self::ProbeResp),
            8 => Ok(Self::JobReq),
            9 => Ok(Self::JobResp),
            10 => Ok(Self::Error),
            11 => Ok(Self::Shutdown),
            _ => bail!("invalid message type: {}", v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    /// Mutual BLAKE3 auth + Hardware AES-256-GCM authenticated encryption on every frame (default)
    Aead,
    /// Mutual BLAKE3 auth + XXH3-64 integrity (for already-encrypted Tailscale/WireGuard links)
    AuthOnly,
}

impl SecurityMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aead" | "aes" | "encrypted" => Ok(Self::Aead),
            "auth-only" | "auth" | "wireguard" => Ok(Self::AuthOnly),
            _ => bail!("invalid security mode '{}': use 'aead' or 'auth-only'", s),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Aead => 1,
            Self::AuthOnly => 0,
        }
    }

    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Aead),
            0 => Ok(Self::AuthOnly),
            _ => bail!("invalid security mode byte: {}", v),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub msg_type: MsgType,
    pub codec: u8,
    pub level: i8,
    pub flags: u8,
    pub chunk_id: u64,
    pub orig_len: u32,
    pub payload_len: u32,
    pub xxh3: u64,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&FRAME_MAGIC);
        buf[4] = self.msg_type as u8;
        buf[5] = self.codec;
        buf[6] = self.level as u8;
        buf[7] = self.flags;
        buf[8..16].copy_from_slice(&self.chunk_id.to_le_bytes());
        buf[16..20].copy_from_slice(&self.orig_len.to_le_bytes());
        buf[20..24].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[24..32].copy_from_slice(&self.xxh3.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self> {
        if buf[0..4] != FRAME_MAGIC {
            bail!("invalid frame magic: {:?}", &buf[0..4]);
        }
        Ok(Self {
            msg_type: MsgType::from_u8(buf[4])?,
            codec: buf[5],
            level: buf[6] as i8,
            flags: buf[7],
            chunk_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            orig_len: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            payload_len: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            xxh3: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        })
    }
}

/// Hardware-accelerated session crypto context with reusable single-syscall coalesced wire buffer.
/// Uses independent directional nonce counters so TX and RX can run concurrently on full-duplex cloned TcpStreams!
#[derive(Clone)]
pub struct StreamCipher {
    cipher: Option<Aes256Gcm>,
    stream_id: u16,
    tx_dir: u8,
    rx_dir: u8,
    tx_seq: u64,
    rx_seq: u64,
    tx_wire_buf: Vec<u8>,
}

impl StreamCipher {
    pub fn new(session_key: [u8; 32], mode: SecurityMode, stream_id: u16, is_client: bool) -> Self {
        let cipher = match mode {
            SecurityMode::Aead => Some(Aes256Gcm::new_from_slice(&session_key).unwrap()),
            SecurityMode::AuthOnly => None,
        };
        Self {
            cipher,
            stream_id,
            tx_dir: if is_client { 0x01 } else { 0x02 },
            rx_dir: if is_client { 0x02 } else { 0x01 },
            tx_seq: 1,
            rx_seq: 1,
            tx_wire_buf: Vec::new(),
        }
    }

    #[inline]
    fn make_nonce(dir: u8, stream_id: u16, seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = dir;
        n[1..3].copy_from_slice(&stream_id.to_le_bytes());
        n[3] = 0;
        n[4..12].copy_from_slice(&seq.to_le_bytes());
        n
    }

    #[allow(dead_code)]
    pub fn is_aead(&self) -> bool {
        self.cipher.is_some()
    }

    /// Write a frame in ONE single coalesced `write_all` syscall (`[32B hdr | payload | 16B tag]`).
    /// Eliminates tiny 32B/16B TCP packets under `TCP_NODELAY`, maximizing MSS packing & Wi-Fi A-MPDU / Jumbo bursts!
    pub fn write_frame<W: Write>(
        &mut self,
        writer: &mut W,
        mut header: FrameHeader,
        payload: &mut [u8],
    ) -> Result<()> {
        header.payload_len = payload.len() as u32;
        if header.xxh3 == 0 && !payload.is_empty() {
            header.xxh3 = xxh3_64(payload);
        }

        if let Some(ref cipher) = self.cipher {
            header.flags |= FLAG_AEAD;
            let hdr_bytes = header.encode();
            let nonce_bytes = Self::make_nonce(self.tx_dir, self.stream_id, self.tx_seq);
            self.tx_seq += 1;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let tag = cipher
                .encrypt_in_place_detached(nonce, &hdr_bytes, payload)
                .map_err(|_| anyhow::anyhow!("AEAD encrypt failed"))?;

            let total = HEADER_LEN + payload.len() + AEAD_TAG_LEN;
            self.tx_wire_buf.clear();
            if self.tx_wire_buf.capacity() < total {
                self.tx_wire_buf.reserve(total - self.tx_wire_buf.capacity());
            }
            self.tx_wire_buf.extend_from_slice(&hdr_bytes);
            self.tx_wire_buf.extend_from_slice(payload);
            self.tx_wire_buf.extend_from_slice(tag.as_slice());
            writer.write_all(&self.tx_wire_buf)?;
        } else {
            let hdr_bytes = header.encode();
            let total = HEADER_LEN + payload.len();
            self.tx_wire_buf.clear();
            if self.tx_wire_buf.capacity() < total {
                self.tx_wire_buf.reserve(total - self.tx_wire_buf.capacity());
            }
            self.tx_wire_buf.extend_from_slice(&hdr_bytes);
            self.tx_wire_buf.extend_from_slice(payload);
            writer.write_all(&self.tx_wire_buf)?;
        }
        Ok(())
    }

    /// Write an immutable slice in ONE coalesced `write_all` syscall (encrypting in-place inside `tx_wire_buf` if AEAD!).
    pub fn write_frame_slice<W: Write>(
        &mut self,
        writer: &mut W,
        mut header: FrameHeader,
        payload: &[u8],
    ) -> Result<()> {
        header.payload_len = payload.len() as u32;
        if header.xxh3 == 0 && !payload.is_empty() {
            header.xxh3 = xxh3_64(payload);
        }

        if let Some(ref cipher) = self.cipher {
            header.flags |= FLAG_AEAD;
            let hdr_bytes = header.encode();
            let nonce_bytes = Self::make_nonce(self.tx_dir, self.stream_id, self.tx_seq);
            self.tx_seq += 1;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let total = HEADER_LEN + payload.len() + AEAD_TAG_LEN;
            self.tx_wire_buf.clear();
            if self.tx_wire_buf.capacity() < total {
                self.tx_wire_buf.reserve(total - self.tx_wire_buf.capacity());
            }
            self.tx_wire_buf.extend_from_slice(&hdr_bytes);
            self.tx_wire_buf.extend_from_slice(payload);
            let tag = cipher
                .encrypt_in_place_detached(nonce, &hdr_bytes, &mut self.tx_wire_buf[HEADER_LEN..])
                .map_err(|_| anyhow::anyhow!("AEAD encrypt failed"))?;
            self.tx_wire_buf.extend_from_slice(tag.as_slice());
            writer.write_all(&self.tx_wire_buf)?;
        } else {
            let hdr_bytes = header.encode();
            let total = HEADER_LEN + payload.len();
            self.tx_wire_buf.clear();
            if self.tx_wire_buf.capacity() < total {
                self.tx_wire_buf.reserve(total - self.tx_wire_buf.capacity());
            }
            self.tx_wire_buf.extend_from_slice(&hdr_bytes);
            self.tx_wire_buf.extend_from_slice(payload);
            writer.write_all(&self.tx_wire_buf)?;
        }
        Ok(())
    }

    /// Read a frame into a reusable buffer (avoids reallocating Vec on every chunk).
    /// Enforces `max_frame_bytes` BEFORE allocation to block OOM DoS.
    pub fn read_frame_into<R: Read>(
        &mut self,
        reader: &mut R,
        buf: &mut Vec<u8>,
        max_frame_bytes: usize,
    ) -> Result<FrameHeader> {
        let mut hdr_bytes = [0u8; HEADER_LEN];
        reader.read_exact(&mut hdr_bytes)?;
        let header = FrameHeader::decode(&hdr_bytes)?;
        let payload_len = header.payload_len as usize;
        if payload_len > max_frame_bytes {
            bail!(
                "frame payload {} exceeds hard limit {}",
                payload_len,
                max_frame_bytes
            );
        }

        buf.resize(payload_len, 0);
        if payload_len > 0 {
            reader.read_exact(buf)?;
        }

        if let Some(ref cipher) = self.cipher {
            if (header.flags & FLAG_AEAD) == 0 {
                bail!("security downgrade rejected: expected AEAD flag on encrypted session");
            }
            let mut tag_bytes = [0u8; AEAD_TAG_LEN];
            reader.read_exact(&mut tag_bytes)?;
            let nonce_bytes = Self::make_nonce(self.rx_dir, self.stream_id, self.rx_seq);
            self.rx_seq += 1;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let tag = Tag::from_slice(&tag_bytes);
            cipher
                .decrypt_in_place_detached(nonce, &hdr_bytes, buf, tag)
                .map_err(|_| anyhow::anyhow!("AEAD authentication/decryption failed (tampered or wrong key)"))?;
        } else if (header.flags & FLAG_AEAD) != 0 {
            bail!("unexpected AEAD flag on auth-only session");
        }

        if payload_len > 0 && header.xxh3 != 0 {
            let actual = xxh3_64(buf);
            if actual != header.xxh3 {
                bail!(
                    "frame checksum mismatch on chunk {}: expected {:016x}, got {:016x}",
                    header.chunk_id,
                    header.xxh3,
                    actual
                );
            }
        }
        Ok(header)
    }
}

/// Constant-time 32-byte MAC comparison via `blake3::Hash` (backed by `constant_time_eq`).
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    blake3::Hash::from(*a) == blake3::Hash::from(*b)
}

fn psk_key(token: &str) -> [u8; 32] {
    blake3::derive_key("hpc-squizze-v1-psk", token.as_bytes())
}

fn compute_mac(psk: &[u8; 32], label: &[u8], client_nonce: &[u8; 32], server_nonce: &[u8; 32], mode: u8, stream_id: u16) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(psk);
    hasher.update(label);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(&[mode]);
    hasher.update(&stream_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn derive_session_key(psk: &[u8; 32], client_nonce: &[u8; 32], server_nonce: &[u8; 32], stream_id: u16) -> [u8; 32] {
    let mut material = Vec::with_capacity(98);
    material.extend_from_slice(psk);
    material.extend_from_slice(client_nonce);
    material.extend_from_slice(server_nonce);
    material.extend_from_slice(&stream_id.to_le_bytes());
    blake3::derive_key("hpc-squizze-v1-session-key", &material)
}

/// Deep OS-aware TCP socket tuning for Wi-Fi 6 / Gigabit / 2.5GbE / Tailscale links:
/// - `TCP_NODELAY` (paired with single-syscall coalesced framing -> zero tiny segments + zero Nagle stall)
/// - Linux: per-socket `TCP_CONGESTION=bbr`, `TCP_NOTSENT_LOWAT=128KiB`, `TCP_QUICKACK=1`,
///   preserves kernel dynamic `tcp_moderate_rcvbuf` autotuning up to 16 MiB, sets DSCP AF41 (`0x88`) for WMM QoS!
/// - Windows: 4 MiB Winsock send/recv buffers + TCP Keepalive!
pub fn tune_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let sock = socket2::SockRef::from(stream);

    // On Linux, do NOT override SO_SNDBUF/SO_RCVBUF so kernel TCP dynamic autotuning (up to 16 MiB) stays active!
    // On Windows/macOS, explicitly request 4 MiB socket buffers for high-BDP scaling.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
        let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    }

    // v6 Wi-Fi-Native: Keep IP_TOS = 0x00 (WMM Best Effort AC_BE) by default!
    // Mapping bulk transfers to WMM Video (0x88 / AC_VI) truncates 802.11ax A-MPDU TXOP to 3-4ms
    // and increases wireless collisions; AC_BE unlocks full 64-256-frame A-MPDU aggregation bursts.
    let _ = sock.set_tos(0x00);

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    let _ = sock.set_tcp_keepalive(&keepalive);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            // 1. Prefer TCP BBR per-socket (ignores random Wi-Fi packet loss; falls back silently if unavailable)
            let bbr = b"bbr\0";
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                bbr.as_ptr() as *const libc::c_void,
                (bbr.len() - 1) as libc::socklen_t,
            );
            // 2. TCP_NOTSENT_LOWAT = 128 KiB -> prevents stale kernel TX queue bloat while keeping NIC fed
            let lowat: libc::c_int = 131_072;
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                &lowat as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            // 3. Disable 40ms delayed ACK stalls on Linux
            let one: libc::c_int = 1;
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok(())
}

/// Re-arm Linux `TCP_QUICKACK` (kernel resets it after ACKs) to prevent 40ms delayed-ACK stalls.
#[inline]
pub fn arm_quickack(_stream: &TcpStream) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = _stream.as_raw_fd();
        let one: libc::c_int = 1;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

pub fn tune_tcp_listener(socket: &Socket) -> Result<()> {
    let _ = socket.set_reuse_address(true);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    }
    Ok(())
}

/// Client-side mutual BLAKE3 handshake -> returns initialized StreamCipher.
pub fn client_handshake(
    stream: &mut TcpStream,
    token: &str,
    mode: SecurityMode,
    stream_id: u16,
    req_threads: u16,
    req_mem_mb: u32,
) -> Result<(StreamCipher, WorkerCaps)> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let psk = psk_key(token);
    let mut client_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_nonce);

    // 1. Send HelloClient: [client_nonce:32][mode:1][stream_id:2][req_threads:2][req_mem_mb:4] = 41 bytes
    let mut hello = Vec::with_capacity(41);
    hello.extend_from_slice(&client_nonce);
    hello.push(mode.as_u8());
    hello.extend_from_slice(&stream_id.to_le_bytes());
    hello.extend_from_slice(&req_threads.to_le_bytes());
    hello.extend_from_slice(&req_mem_mb.to_le_bytes());

    let mut plain = StreamCipher::new([0u8; 32], SecurityMode::AuthOnly, stream_id, true);
    plain.write_frame_slice(
        stream,
        FrameHeader {
            msg_type: MsgType::HelloClient,
            codec: 0,
            level: 0,
            flags: 0,
            chunk_id: 0,
            orig_len: 0,
            payload_len: 0,
            xxh3: 0,
        },
        &hello,
    )?;

    // 2. Receive HelloServer: [server_nonce:32][server_mac:32] (no host metadata leaked pre-auth!)
    let mut buf = Vec::new();
    let hdr = plain
        .read_frame_into(stream, &mut buf, 64 * 1024)
        .context("failed reading worker HelloServer")?;
    if hdr.msg_type == MsgType::Error {
        bail!("worker rejected connection: {}", String::from_utf8_lossy(&buf));
    }
    if hdr.msg_type != MsgType::HelloServer || buf.len() != 64 {
        bail!("unexpected HelloServer frame");
    }
    let server_nonce: [u8; 32] = buf[0..32].try_into().unwrap();
    let server_mac: [u8; 32] = buf[32..64].try_into().unwrap();
    let expected_server_mac = compute_mac(&psk, b"server-auth", &client_nonce, &server_nonce, mode.as_u8(), stream_id);
    if !ct_eq_32(&server_mac, &expected_server_mac) {
        bail!("worker authentication failed (mismatched --token or MITM)");
    }

    // 3. Send AuthClient: [client_mac:32]
    let client_mac = compute_mac(&psk, b"client-auth", &client_nonce, &server_nonce, mode.as_u8(), stream_id);
    plain.write_frame_slice(
        stream,
        FrameHeader {
            msg_type: MsgType::AuthClient,
            codec: 0,
            level: 0,
            flags: 0,
            chunk_id: 0,
            orig_len: 0,
            payload_len: 0,
            xxh3: 0,
        },
        &client_mac,
    )?;

    // 4. Derive session cipher and read authenticated/encrypted AuthOk carrying WorkerCaps
    let session_key = derive_session_key(&psk, &client_nonce, &server_nonce, stream_id);
    let mut cipher = StreamCipher::new(session_key, mode, stream_id, true);

    let hdr = cipher.read_frame_into(stream, &mut buf, 64 * 1024)?;
    if hdr.msg_type == MsgType::Error {
        bail!("worker auth failed: {}", String::from_utf8_lossy(&buf));
    }
    if hdr.msg_type != MsgType::AuthOk {
        bail!("expected AuthOk, got {:?}", hdr.msg_type);
    }
    let caps = WorkerCaps::decode(&buf)?;

    // Clear short handshake timeout for streaming jobs
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    Ok((cipher, caps))
}

/// Server-side mutual BLAKE3 handshake -> returns (StreamCipher, requested_threads, requested_mem_mb, stream_id).
/// WorkerCaps is sent ONLY after mutual authentication succeeds, encrypted under the session cipher.
pub fn server_handshake(
    stream: &mut TcpStream,
    token: &str,
    allow_auth_only: bool,
    caps: &WorkerCaps,
) -> Result<(StreamCipher, u16, u32, u16)> {
    // Pre-auth anti-slowloris timeout
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let psk = psk_key(token);
    let mut plain = StreamCipher::new([0u8; 32], SecurityMode::AuthOnly, 0, false);
    let mut buf = Vec::new();

    // 1. Read HelloClient
    let hdr = plain.read_frame_into(stream, &mut buf, 4096)?;
    if hdr.msg_type != MsgType::HelloClient || buf.len() != 41 {
        bail!("invalid HelloClient frame");
    }
    let client_nonce: [u8; 32] = buf[0..32].try_into().unwrap();
    let mode = SecurityMode::from_u8(buf[32])?;
    let stream_id = u16::from_le_bytes(buf[33..35].try_into().unwrap());
    let req_threads = u16::from_le_bytes(buf[35..37].try_into().unwrap());
    let req_mem_mb = u32::from_le_bytes(buf[37..41].try_into().unwrap());

    if mode == SecurityMode::AuthOnly && !allow_auth_only {
        let _ = plain.write_frame_slice(
            stream,
            FrameHeader {
                msg_type: MsgType::Error,
                codec: 0,
                level: 0,
                flags: 0,
                chunk_id: 0,
                orig_len: 0,
                payload_len: 0,
                xxh3: 0,
            },
            b"worker requires AEAD encryption (--security aead)",
        );
        bail!("client attempted auth-only while worker requires AEAD");
    }

    // 2. Send HelloServer: [server_nonce:32][server_mac:32] (no pre-auth host info disclosure)
    let mut server_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut server_nonce);
    let server_mac = compute_mac(&psk, b"server-auth", &client_nonce, &server_nonce, mode.as_u8(), stream_id);

    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&server_nonce);
    resp.extend_from_slice(&server_mac);
    plain.write_frame_slice(
        stream,
        FrameHeader {
            msg_type: MsgType::HelloServer,
            codec: 0,
            level: 0,
            flags: 0,
            chunk_id: 0,
            orig_len: 0,
            payload_len: 0,
            xxh3: 0,
        },
        &resp,
    )?;

    // 3. Read AuthClient
    let hdr = plain.read_frame_into(stream, &mut buf, 1024)?;
    if hdr.msg_type != MsgType::AuthClient || buf.len() != 32 {
        bail!("invalid AuthClient frame");
    }
    let client_mac: [u8; 32] = buf[0..32].try_into().unwrap();
    let expected_client_mac = compute_mac(&psk, b"client-auth", &client_nonce, &server_nonce, mode.as_u8(), stream_id);
    if !ct_eq_32(&client_mac, &expected_client_mac) {
        let _ = plain.write_frame_slice(
            stream,
            FrameHeader {
                msg_type: MsgType::Error,
                codec: 0,
                level: 0,
                flags: 0,
                chunk_id: 0,
                orig_len: 0,
                payload_len: 0,
                xxh3: 0,
            },
            b"authentication failed",
        );
        bail!("client auth MAC mismatch");
    }

    // 4. Derive session cipher and send WorkerCaps encrypted inside AuthOk
    let session_key = derive_session_key(&psk, &client_nonce, &server_nonce, stream_id);
    let mut cipher = StreamCipher::new(session_key, mode, stream_id, false);
    let mut caps_bytes = caps.encode();
    cipher.write_frame(
        stream,
        FrameHeader {
            msg_type: MsgType::AuthOk,
            codec: 0,
            level: 0,
            flags: 0,
            chunk_id: 0,
            orig_len: caps_bytes.len() as u32,
            payload_len: caps_bytes.len() as u32,
            xxh3: 0,
        },
        &mut caps_bytes,
    )?;

    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    Ok((cipher, req_threads, req_mem_mb, stream_id))
}

#[derive(Debug, Clone)]
pub struct WorkerCaps {
    pub hostname: String,
    pub os_arch: String,
    pub cpu_brand: String,
    pub total_threads: u16,
    pub max_threads: u16,
    pub avail_mem_mb: u32,
    pub max_mem_mb: u32,
}

impl WorkerCaps {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.total_threads.to_le_bytes());
        out.extend_from_slice(&self.max_threads.to_le_bytes());
        out.extend_from_slice(&self.avail_mem_mb.to_le_bytes());
        out.extend_from_slice(&self.max_mem_mb.to_le_bytes());
        for s in [&self.hostname, &self.os_arch, &self.cpu_brand] {
            let b = s.as_bytes();
            let len = (b.len().min(255)) as u8;
            out.push(len);
            out.extend_from_slice(&b[..len as usize]);
        }
        out
    }

    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            bail!("truncated WorkerCaps");
        }
        let total_threads = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let max_threads = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let avail_mem_mb = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let max_mem_mb = u32::from_le_bytes(data[8..12].try_into().unwrap());
        data = &data[12..];

        let mut strings = Vec::with_capacity(3);
        for _ in 0..3 {
            if data.is_empty() {
                bail!("truncated WorkerCaps string");
            }
            let len = data[0] as usize;
            data = &data[1..];
            if data.len() < len {
                bail!("truncated WorkerCaps string body");
            }
            strings.push(String::from_utf8_lossy(&data[..len]).into_owned());
            data = &data[len..];
        }

        Ok(Self {
            hostname: strings.remove(0),
            os_arch: strings.remove(0),
            cpu_brand: strings.remove(0),
            total_threads,
            max_threads,
            avail_mem_mb,
            max_mem_mb,
        })
    }
}
