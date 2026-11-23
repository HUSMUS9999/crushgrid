<p align="center">
  <img src="assets/logo.png" alt="squiz-archive" width="128" height="128" />
</p>

<h1 align="center">squiz-archive</h1>

<p align="center">
  <a href="https://github.com/HUSMUS9999/squiz-archive/releases"><img alt="Release" src="https://img.shields.io/github/v/release/HUSMUS9999/squiz-archive" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
</p>

`squiz-archive` distributes file and directory compression across multiple machines over LAN, VPN (Tailscale/WireGuard), or cloud networks. It ships as a single ~2.4 MiB executable with statically linked `libzstd` and `liblzma` codecs (plus pure-Rust LZ4). The same binary runs as coordinator or worker on Linux and Windows (macOS builds from source).

## Overview

- **Multi-node scaling:** Add any number of local, LAN, VPN, or cloud workers via `--cluster cluster.conf`, repeated `--node` flags, or interactive selection (`-i` / `--pick`).
- **Resource ceilings:** Cap threads (`N`, `N%`, `auto`, `max`), coordinator RAM (`--mem-limit`, default `2G`), and per-node TX bandwidth (`bw=` in bytes/sec). Workers enforce server-side `--max-threads` and `--max-mem` (default `4G`) ceilings.
- **Codecs and deduplication:** Zstd (with Long-Distance Matching enabled on slabs >= 1 MiB), LZMA2 (`liblzma`), and LZ4 (`lz4_flex`). `.sqz` directory archives group files into solid blocks by file class and extension, deduplicate identical slabs via `BLAKE3`, and store incompressible slabs raw after a `<0.05 ms` LZ4 entropy probe.
- **Seekable formats:** `.zst` writes standard Zstd Seekable Format (`0x184D2A5E`), readable by upstream `zstd -d` or `squiz-archive decompress` (`decompress` requires seekable `.zst` or `.sqz`). `.sqz` adds a compressed directory manifest, per-slab `XXH3-64` checksums, and a whole-stream `BLAKE3` digest verified on single-file `decompress`.
- **Transport security:** Mutual `BLAKE3` PSK challenge-response (32-byte OS CSPRNG nonces, constant-time MAC check) followed by per-session 256-bit `AES-256-GCM` with header AAD (`--security aead`, default). Host capabilities are sent only after authentication succeeds. `--security auth-only` is opt-in (requires worker `--allow-auth-only`) for already-encrypted WireGuard/Tailscale tunnels.

## Install

Download prebuilt binaries from [Releases](https://github.com/HUSMUS9999/squiz-archive/releases), or build from source (Rust 1.85+):

```bash
git clone https://github.com/HUSMUS9999/squiz-archive.git
cd squiz-archive

# Native build (AVX2 / AVX-512 / AES-NI)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Portable x86_64-v3 + AES-NI build (Linux)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq" cargo build --release

# Cross-compile Windows .exe from Linux (requires mingw-w64)
rustup target add x86_64-pc-windows-gnu
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq" cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

### 1. Start workers

```bash
# Generate a shared token once: openssl rand -hex 32
export SQUIZ_TOKEN="<64-hex-char-token>"

# Worker reads SQUIZ_TOKEN from the environment (hard ceilings enforced server-side)
squiz-archive worker --bind 0.0.0.0:7878 --max-threads 16 --max-mem 8G
```

### 2. Configure nodes (`cluster.conf`)

Copy `cluster.conf.example` and add as many LAN, VPN, or cloud workers as needed:

```ini
token = <64-hex-char-token>
security = aead
wire_codec = auto
mem_limit = 4G
streams = 2

node = local:threads=auto,mem=4G
node = 192.168.1.40:7878:threads=max,mem=8G
node = 100.64.0.10:7878:threads=max,mem=16G
# bw= is in bytes/sec (e.g. 10M = 10 MiB/s ~= 84 Mbps)
node = worker1.example.com:7878:threads=32,mem=16G,streams=6,bw=10M
```

### 3. Probe, pack, compress, and extract

```bash
# Check reachability, CPU/RAM ceilings, RTT, and link throughput
squiz-archive probe --cluster cluster.conf

# Pack a directory (add -i / --pick to toggle nodes and limits interactively)
squiz-archive pack /path/to/data -o backup.sqz --cluster cluster.conf --codec zstd --level 12 --block-size 8M

# Inspect metadata, dedup savings, and file list
squiz-archive inspect backup.sqz --list

# Extract a directory archive
squiz-archive unpack backup.sqz -o ./restored --cluster cluster.conf

# Single-file seekable .zst (upstream `zstd -d` compatible)
squiz-archive compress large.bin -o large.bin.zst --cluster cluster.conf --codec zstd --level 19
squiz-archive decompress large.bin.zst -o large.bin --cluster cluster.conf

# Local-vs-cluster and wire throughput benchmarks
squiz-archive bench sample.bin --cluster cluster.conf --codec zstd --level 19
squiz-archive net-bench --cluster cluster.conf --streams 4
```

See [`docs/CLUSTER_SETUP.md`](docs/CLUSTER_SETUP.md) for LAN firewalls, Tailscale/WireGuard meshes, public cloud deployment (`systemd`, Windows Scheduled Task), and optional OS TCP tuning scripts (`scripts/tune-linux.sh`, `scripts/tune-windows.ps1`).

## Benchmarks

Measured on a 3-node testbed over a shared 5 GHz wireless LAN (~150 Mbps bidirectional ceiling) with `AES-256-GCM` enabled (`--security aead`) and `BLAKE3` round-trip verification:

- Coordinator: Windows x86_64, 6C/12T (2.6 GHz), 16 GiB RAM
- Worker 1: Linux x86_64, 16C/32T (2.5-5.4 GHz), 30 GiB RAM
- Worker 2: Linux x86_64, 12C/20T (2.1-4.9 GHz), 62 GiB RAM

With `threads=auto` and remote workers active, 2 local threads are reserved on the coordinator for network I/O and encryption (62 active compute threads total: 10 + 32 + 20).

| Workload | Codec | Local (12T) | Cluster (62T) | Speedup | Ratio |
|---|---|---:|---:|---:|---:|
| 256 MiB mixed-entropy | `zstd L19` (2M blk) | 21.26 s (12.0 MiB/s) | 7.30 s (35.1 MiB/s) | 2.91x | 3.69x |
| 256 MiB mixed-entropy | `lzma2 L6` (2M blk) | 6.13 s (41.7 MiB/s) | 3.82 s (67.1 MiB/s) | 1.61x | 3.71x |
| 128 MiB PE binaries | `lzma2 L6` (2M blk) | 5.59 s (22.9 MiB/s) | 3.23 s (39.6 MiB/s) | 1.73x | 3.38x |
| 1.25 GiB directory (23k files) | `zstd L12` (`.sqz`, 4M) | - | 90.6 s (312 MiB out) | - | 4.11x |
| 185.5 GiB CSV dataset (107 files) | `zstd L9` (`.sqz`, 8M) | - | 2748 s (45.2 GiB out, 69.1 MiB/s) | - | 4.10x |
| 256 MiB parallel decompress | `zstd` (`auto`) | 0.10 s (2566 MiB/s) | 0.12 s (2108 MiB/s) | 0.83x* | - |

*\*In `auto` mode, fast Zstd decompression stays local because local decode speed exceeds wireless RX bandwidth; the 20 ms delta is cluster setup overhead. Use `--schedule force-all` to force remote decompression on fast wired links.*

On wired Gigabit, 2.5GbE, 10GbE, or cloud VPC links, scaling is compute-bound rather than link-bound.

## License

MIT. See [LICENSE](LICENSE).
