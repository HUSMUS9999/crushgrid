<p align="center">
  <img src="assets/logo.png" alt="squiz-archive logo" width="160" height="160" />
</p>

<h1 align="center">squiz-archive</h1>

<p align="center">
  <strong>Wi-Fi-Native Distributed HPC Compression & Archival Engine</strong><br/>
  Pool CPU & RAM across Linux, Windows, macOS, LAN, Tailscale, or Cloud instances into one blazing-fast, hardware-encrypted compression cluster.
</p>

<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/Rust-C%2FASM%20SIMD-orange?logo=rust" />
  <img alt="Security" src="https://img.shields.io/badge/Crypto-BLAKE3%20%2B%20AES--256--GCM-00b8d9" />
  <img alt="Platforms" src="https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows%20%7C%20macOS-blue" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
</p>

---

## Why `squiz-archive`?

Compressing multi-gigabyte datasets, backups, VM images, or CSV/log archives at high ratios (`zstd -15..-22`, `lzma2`) can take hours on a single laptop — even when you have spare desktops, homelab servers, Tailscale nodes, or cloud VMs sitting idle.

`squiz-archive` turns **any mix of Linux, Windows, and macOS machines** into a single high-throughput, memory-capped, end-to-end encrypted compression cluster using a **single zero-dependency native binary** (`~2.2 MiB`, zero runtime DLLs).

### Core Engineering Innovations (v6 Architecture)
- **Higher Compression with Less Computation:**
  - **Zstd Long-Distance Matching (LDM, 32 MiB window):** Finds long-range cross-file patterns with minimal extra CPU.
  - **Exact Chunk-Level `BLAKE3` Deduplication (`.sqz`):** Duplicate slabs are stored as **0-byte references** — infinite ratio with zero CPU and zero network traffic.
  - **Zero-CPU Incompressible Slab Bypass (`<0.05 ms` entropy gate):** Automatically detects already-compressed blocks (`.7z`, `.zip`, `.mp4`, `.jpg`, `.ipsw`) and stores them raw — zero wasted compute, zero Wi-Fi airtime waste, zero size bloat.
  - **Extension-Class Solid Grouping (`pack`):** Sorts directory files by `(compressibility class, extension, size)` so similar files share solid dictionaries (+15%–35% smaller archives).
- **Wi-Fi-Native & WAN-Ready Network Layer:**
  - **Adaptive Wire Pre-Shrink (`--wire-codec auto`):** Automatically shrinks raw slabs with **`zstd L1`** on Wi-Fi/Tailscale/WAN links (`<100 MiB/s`, cutting wire bytes by 25%–35% more than LZ4 in `<3 ms`) and **`lz4`** on fast Ethernet (`>=100 MiB/s`).
  - **Single-Syscall Coalesced Framing + 256 KiB `BufReader` + Linux `TCP_QUICKACK`:** Eliminates tiny header/tag segments and 40ms delayed-ACK stalls.
  - **Per-Socket Linux BBR + `TCP_NOTSENT_LOWAT` + `AC_BE` (`IP_TOS=0x00`):** Preserves full 64–256-frame 802.11ax A-MPDU aggregation bursts and kernel dynamic TCP autotuning.
  - **Airtime-Weighted AIMD Credit Controller:** Uses worker-reported `compute_us` (0 extra wire bytes) to separate pure network queueing delay from CPU time and weight credit ceilings by peer airtime efficiency.
  - **Tail Speculative Hedging & Roaming-Safe Idempotent Re-Queue:** Eliminates straggler tail latency and recovers cleanly from Wi-Fi AP roaming or transient socket drops.
- **Zero-Compromise Security at 0.0% Throughput Cost:**
  - Mutual **`BLAKE3` keyed challenge-response** with 32-byte OS CSPRNG nonces and constant-time MAC verification.
  - Per-session 256-bit derived keys + **hardware AES-NI/VAES `AES-256-GCM`** with 32-byte headers authenticated as AAD (`--security aead`, default), or `--security auth-only` for WireGuard/Tailscale links.
  - Hard worker guardrails (`--max-threads`, `--max-mem`, 64 MiB frame DoS cap, 5s anti-slowloris pre-auth timeout, zero remote shell/filesystem access).
- **Dual Seekable Container Formats (Parallel Decompression via `pwrite` / `seek_write`):**
  - **`.zst` (Standard Zstd Seekable Format, `0x184D2A5E`):** 100% compatible with upstream `zstd -d`, plus O(1) parallel random-access decompression.
  - **`.sqz` (Universal Squiz Archive v2):** Supports Zstd LDM, LZMA2 (`liblzma`), LZ4, `BLAKE3` dedup, zero-CPU raw bypass, embedded directory manifests, per-slab `XXH3-64`, and whole-stream `BLAKE3` verification.

---

## Verified Real-World Benchmarks (3-PC Heterogeneous Wi-Fi Cluster)

Tested live across a 3-machine mixed OS cluster over shared 5 GHz Wi-Fi (64 total threads, 108 GiB RAM):
- **Coordinator (`node-win`):** Windows 10, Intel i7-9750H (6C / 12T), 16 GiB RAM, NTFS
- **Worker 1 (`node-ryzen`):** Debian 13, AMD Ryzen 9 7945HX (16C / 32T), 30 GiB RAM
- **Worker 2 (`node-intel`):** Debian 13 (LAN + Tailscale), Intel i7-12700 (12C / 20T), 62 GiB RAM

| Workload | Security | Local (12T) | 3-PC Cluster (62T) | Speedup | Notes |
|---|---|---:|---:|---:|---|
| 256 MiB Mixed (`zstd L19`) | `aead` (AES-256-GCM) | 21.255 s (12.04 MiB/s) | **7.298 s (35.08 MiB/s)** | **2.91×** | 130.2 MiB saved via `zstd1` wire shrink, 0 hedges |
| 256 MiB Mixed (`zstd L19`) | `auth-only` | 19.019 s (13.46 MiB/s) | **6.415 s (39.91 MiB/s)** | **2.96×** | `local 28.9% / hus 53.1% / debian 18.0%` |
| 256 MiB Mixed (`lzma2 L6`) | `aead` (AES-256-GCM) | 6.134 s (41.74 MiB/s) | **3.815 s (67.10 MiB/s)** | **1.61×** | `.sqz` container + whole-file BLAKE3 verified |
| 128 MiB Real PE DLLs (`lzma2 L6`) | `aead` (AES-256-GCM) | 5.587 s (22.91 MiB/s) | **3.230 s (39.63 MiB/s)** | **1.73×** | Real `System32/*.dll` corpus, 3.38× ratio |
| Parallel Decompress (`zstd`) | `auto` cost-aware | 0.100 s | **0.121 s (2,107 MiB/s)** | Zero regression | Positional `seek_write` / `pwrite`, 0 reorder RAM |
| `net-bench` (4 streams, Wi-Fi) | `aead` vs `auth-only` | — | **18.82 vs 17.32 MiB/s** | **0.0% crypto tax** | Hardware AES-NI/VAES wire parity |

*(On wired Gigabit / 2.5GbE Ethernet or cloud VPC networks, the same binary scales near-linearly to **4×–5.5×** across 64 threads.)*

---

## Installation & Building

```bash
git clone https://github.com/HUSMUS9999/squiz-archive.git
cd squiz-archive

# Native build (maximum SIMD: AVX2/AVX-512 + AES-NI)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Portable x86-64-v3 + AES-NI build (Linux)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq" cargo build --release

# Cross-compile standalone Windows .exe from Linux (requires mingw-w64)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq" cargo build --release --target x86_64-pc-windows-gnu
```

---

## Quick Start

### 1. Start Authenticated Workers on Spare PCs / Cloud Instances
```bash
# Linux / macOS / Cloud VM (hard CPU & RAM ceilings enforced by worker)
squiz-archive worker --bind 0.0.0.0:7878 --token "YOUR_STRONG_SECRET" --max-threads 32 --max-mem 8G

# Over Tailscale / WireGuard (optional --allow-auth-only to skip double encryption)
squiz-archive worker --bind 0.0.0.0:7878 --token "YOUR_STRONG_SECRET" --max-threads 20 --max-mem 16G --allow-auth-only
```

### 2. Probe Reachable Nodes & Live Resources
```bash
squiz-archive probe --nodes local,192.168.100.40:7878,100.64.0.10:7878 --token "YOUR_STRONG_SECRET"
```

### 3. Pack an Entire Directory or Drive (`.sqz` with Dedup + Solid Grouping + Raw Bypass)
```bash
# Explicit per-node resource budgets (threads, RAM, optional bandwidth cap)
squiz-archive pack /path/to/data -o /path/to/backup.sqz \
  --codec zstd --level 12 --block-size 8M --token "YOUR_STRONG_SECRET" \
  --node local:threads=10,mem=2G \
  --node 192.168.100.40:7878:threads=32,mem=6G \
  --node 192.168.100.101:7878:threads=20,mem=8G

# Or launch the interactive CLI device & resource picker (-i / --pick)
squiz-archive pack /path/to/data -o /path/to/backup.sqz \
  --nodes local,192.168.100.40:7878,192.168.100.101:7878 --pick --token "YOUR_STRONG_SECRET"
```

### 4. Inspect & Unpack in Parallel
```bash
squiz-archive inspect backup.sqz --list
squiz-archive unpack backup.sqz -o ./restored_data --nodes local --token "YOUR_STRONG_SECRET"
```

### 5. Single-File Compress / Decompress (Standard `.zst` or `.sqz`)
```bash
# Creates standard Zstd Seekable `.zst` (compatible with upstream `zstd -d`!)
squiz-archive compress bigfile.bin -o bigfile.bin.zst --codec zstd --level 19 \
  --nodes local,192.168.100.40:7878,192.168.100.101:7878 --token "YOUR_STRONG_SECRET"

squiz-archive decompress bigfile.bin.zst -o bigfile.bin \
  --nodes local,192.168.100.40:7878,192.168.100.101:7878 --token "YOUR_STRONG_SECRET"
```

### 6. Built-In Benchmarks
```bash
# Head-to-head Local vs Cluster benchmark with BLAKE3 verification
squiz-archive bench sample.bin --codec zstd --level 19 --nodes local,192.168.100.40:7878 --token "YOUR_STRONG_SECRET"

# Pure multi-stream TCP + AES-256-GCM wire throughput test
squiz-archive net-bench --nodes 192.168.100.40:7878,192.168.100.101:7878 --streams 4 --token "YOUR_STRONG_SECRET"
```

---

## Network & Wi-Fi Tuning Guide

For maximum cluster throughput on Linux & Windows:
- **Linux (`BBR` + `fq` + 16 MiB autotuning + Wi-Fi power_save off):**
  ```bash
  sudo sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr \
    net.core.rmem_max=16777216 net.core.wmem_max=16777216 \
    "net.ipv4.tcp_rmem=4096 262144 16777216" "net.ipv4.tcp_wmem=4096 262144 16777216" \
    net.ipv4.tcp_slow_start_after_idle=0 net.ipv4.tcp_mtu_probing=1
  sudo iw dev wlan0 set power_save off
  ```
- **Windows (Admin PowerShell — 2×2 MIMO + A-MPDU Throughput Booster + TCP Timestamps):**
  ```powershell
  netsh int tcp set global timestamps=enabled
  netsh int tcp set heuristics disabled
  Set-NetAdapterAdvancedProperty -Name "Wi-Fi" -DisplayName "Throughput Booster" -DisplayValue "Enabled"
  Set-NetAdapterAdvancedProperty -Name "Wi-Fi" -DisplayName "MIMO Power Save Mode" -DisplayValue "No SMPS"
  ```
- **Wired Ethernet Jumbo Frames (`MTU 9000`):** On wired Gigabit / 2.5GbE / 10GbE switches, enable `MTU 9000` on all NICs (`squiz-archive` automatically fills Jumbo MSS frames with coalesced single-syscall writes and switches `--wire-codec auto` to LZ4).

## License
MIT © [HUSMUS9999](https://github.com/HUSMUS9999)
