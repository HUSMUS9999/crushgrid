# Architecture and Security Model

## Pipeline Overview

`crushgrid` uses a pull-based, credit-gated work-stealing pipeline backed by bounded OS threads, `crossbeam-channel` queues, and a hard memory-budget semaphore (`ByteBudget`).

```text
Input File / Sorted Multi-File Stream
  -> Sequential Reader + ByteBudget (--mem-limit)
  -> [BLAKE3 Dedup] -> [Entropy Raw Bypass] -> [Per-Slab Codec Classifier]
  -> Shared MPMC Work Queue (Arc<WorkTask>)
       ├── Local Worker Pool (reserves 1-2 I/O threads on coordinator when remote nodes are active)
       └── Remote Worker Connectors (N parallel full-duplex TCP streams per peer)
            ├── TX Thread: Airtime-Weighted AIMD Credit Gate -> Adaptive Wire Pre-Shrink -> AES-256-GCM -> Single-Syscall Write
            └── RX Thread: 256 KiB BufReader + TCP_QUICKACK -> AES-256-GCM Verify -> Expand -> Result Queue
  -> Bounded Reorder Writer (compression) / Positional pwrite/seek_write (extraction, zero reorder RAM)
```

### Scheduling Details

- **Worker-reported `compute_us`:** Workers pack their pure CPU execution time (microseconds) into the `JobResp` frame header (0 extra wire bytes). The coordinator subtracts `compute_us` from total round-trip time to isolate pure network queueing latency, preventing heavy `lzma2`/`zstd L22` chunks from falsely triggering congestion backoff.
- **Airtime-weighted AIMD credits:** Each peer's maximum in-flight credit ceiling is weighted by its measured link bandwidth and thread count (`probe_bw * threads`), preventing slower peers on shared media from starving faster high-core workers.
- **Tail speculative hedging:** Once the reader reaches EOF, idle local threads speculatively execute the oldest uncompleted remote slabs. First valid result wins; duplicates are discarded in O(1).
- **Fault tolerance and roaming recovery:** Remote data streams enforce 20-second active-flight timeouts. If a peer drops or stalls while slabs are in flight, those slabs are immediately re-queued to healthy nodes and the stream retries connection up to 3 times. Idle timeouts with zero slabs in flight do not drop the connection.
- **Cost-aware decompression (`--schedule auto`):** Compares estimated local multi-core decode throughput against remote link speed. Fast codecs (Zstd, LZ4) stay local over wireless/WAN links unless `--schedule force-all` is set.

## Container Formats

### `.zst` (Standard Zstd Seekable Format)
- Concatenated independent Zstd frames (each with native content size and xxHash checksum) followed by an official Zstd Seekable skippable frame (`0x184D2A5E`, footer magic `0x8F92EAB1`).
- Standard `zstd -d` ignores the skippable frame and decompresses normally.
- `crushgrid decompress` reads the seek table in O(1) and extracts frames in parallel via positional `pwrite` (Unix) / `seek_write` (Windows). Note: `crushgrid decompress` requires a seekable `.zst` or `.sqz` archive.

### `.sqz` v3 (Universal Multi-Codec Container)
- **Header (80 bytes):** magic `SQZA`, version (`3`), primary codec, level, flags, block size, total original size, chunk count, whole-stream `BLAKE3` digest (32 bytes), compressed file manifest offset & length.
- **Data section:** sequential compressed or raw slabs. Deduplicated slabs occupy 0 bytes in the data section.
- **Compressed file manifest (optional, for `pack`):** Zstd-compressed list of relative POSIX paths, stream offsets, file sizes, timestamps, and directory markers. Path extraction strictly rejects absolute paths and `..` components. Note: `pack` archives regular files and directories only (symlinks are skipped; POSIX mode bits and `mtime` are not restored on `unpack`, and empty files/directories with 0 total bytes are rejected).
- **Seek table (36 bytes/entry):** `(comp_offset: u64, comp_len: u32, orig_offset: u64, orig_len: u32, xxh3_64: u64, chunk_flags: u8, slab_codec: u8, reserved: 2B)` followed by a 24-byte trailer (`table_offset`, `num_chunks`, magic `AZQS_V02`).
- Backwards-compatible reader supports v1 `.hsq`, v2 `.sqz`, and v3 `.sqz`.

## Wire Protocol and Security Model

### Frame Layout
- Fixed 32-byte little-endian header: `[magic:4 ("HSQ1")][msg_type:1][codec:1][level:1][flags:1][chunk_id:8][orig_len:4][payload_len:4][xxh3_64:8]`.
- When `--security aead` (default) is active, the 32-byte header is authenticated as Additional Authenticated Data (AAD), the payload is encrypted in-place with `AES-256-GCM`, and the 16-byte authentication tag is appended.
- `[header || payload || tag]` is transmitted in a single coalesced `write_all` call to avoid tiny-packet fragmentation under `TCP_NODELAY`.

### Handshake and Threat Model
1. Client sends `HelloClient` (`client_nonce: 32B`, security mode, stream ID, requested threads/RAM).
2. Server responds with `HelloServer` (`server_nonce: 32B`, `server_mac: 32B` via keyed `BLAKE3`). **No host capabilities are sent before authentication.**
3. Client verifies `server_mac` in constant time (`blake3::Hash` equality) and sends `AuthClient` (`client_mac: 32B`).
4. Server verifies `client_mac` in constant time, derives a per-stream 256-bit key via `BLAKE3::derive_key(psk || client_nonce || server_nonce || stream_id)`, and sends `WorkerCaps` inside the encrypted `AuthOk` frame.
5. Nonces use disjoint direction bits (`0x01` client->server, `0x02` server->client), `stream_id`, and strictly monotonic per-frame sequence numbers.

### Guardrails and Limitations
- **Worker isolation:** Workers process pure byte buffers only; they never execute shell commands or access the filesystem.
- **DoS protection:** 5-second pre-auth timeout; 64 MiB hard max-frame check enforced on both `payload_len` and `orig_len` before allocation; PPMd7 and Bzip3 decoder headers are bounds-checked (<= 64 MiB) before instantiation; `.sqz` seek tables and manifests are validated against file length and capped at 256 MiB; workers clamp requested threads/RAM to server-side `--max-threads` and `--max-mem` ceilings.
- **No forward secrecy:** Session keys are derived from a static PSK and random nonces without an ephemeral Diffie-Hellman exchange. Rotate `CRUSHGRID_TOKEN` periodically, firewall public workers to coordinator IPs, or run inside WireGuard/Tailscale for forward-secret transport.
- **Compression before encryption:** Adaptive wire pre-shrink (`zstd1`/`lz4`) runs inside the AEAD envelope for bulk file transfer performance. Pass `--wire-codec none` if operating in an adversarial chosen-plaintext oracle threat model.
- **Integrity scope:** `.sqz` archives verify per-slab `XXH3-64` on every `decompress` and `unpack`, plus whole-stream `BLAKE3` on single-file `decompress` (unless `--no-verify` is passed). `.zst` seekable archives rely on `libzstd`'s native per-frame XXH64 checksum.
