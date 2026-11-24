<p align="center">
  <img src="assets/logo.png" alt="squiz-archive" width="128" height="128" />
</p>

<h1 align="center">squiz-archive</h1>

<p align="center">
  <a href="https://github.com/HUSMUS9999/squiz-archive/releases"><img alt="Release" src="https://img.shields.io/github/v/release/HUSMUS9999/squiz-archive" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
</p>

`squiz-archive` distributes file and directory compression across multiple machines over LAN, VPN (Tailscale/WireGuard), or cloud networks. It ships as a single executable with statically bundled `libzstd`, `liblzma`, and `libbzip3` (plus pure-Rust PPMd7 and LZ4). The same binary runs as coordinator or worker on Linux and Windows (macOS builds from source).

## Quick Start

You do not need to know compression algorithms or tune flags to get started.

```bash
# 1. Local compression with smart defaults (creates ./backups.sqz)
squiz-archive pack ./backups

# 2. Higher compression without learning codec flags
squiz-archive pack ./backups --preset small

# 3. Extract in parallel (creates ./backups)
squiz-archive unpack backups.sqz

# 4. Plain-English command mode (prints the resolved CLI command; add --dry-run to preview)
squiz-archive do "compress ./logs as small as possible using 50% cpu"
```

### Multi-Node Cluster Setup (2 to 100+ hosts)

```bash
# Generate a 256-bit CSPRNG token and ~/.config/squiz-archive/cluster.conf (0600 on Unix)
squiz-archive init --nodes 192.168.1.40:7878,100.64.0.10:7878

# Start a worker on each contributing host (reads SQUIZ_TOKEN from env)
export SQUIZ_TOKEN="<token-from-init>"
squiz-archive worker --bind 0.0.0.0:7878 --max-mem 8G

# Verify hardware, config, and OS TCP tuning
squiz-archive doctor
squiz-archive probe

# Run on your cluster (auto-discovers cluster.conf; add -i / --pick to select nodes interactively)
squiz-archive pack ./dataset --preset small
```

Run `squiz-archive -h` or `squiz-archive <command> -h` to list all commands and flags.

## Presets

| Preset (`-m` / `--preset`) | Behavior | When to Use |
|---|---|---|
| `fast` | Zstd L3 | Fast scratch backups and high-speed links |
| `balanced` *(default)* | Zstd L9 + LDM | Everyday compression speed and ratio |
| `small` | Per-slab auto: Bzip3 (text/CSV), LZMA2+BCJ (x86 binaries), LZMA2 L6 (mixed), raw bypass (already compressed) | High ratio without slow LZMA2-only wall times |
| `max` | Per-slab auto: Bzip3 16M (text/code), LZMA2+BCJ L9 (binaries), LZMA2 L9 (mixed) | Cold archival storage where smallest size matters |

Power users can override any preset with `--codec zstd|bzip3|ppmd|lzma2|lzma2-bcj|lz4|auto` and `--level N`.

## Install

Download prebuilt binaries from [Releases](https://github.com/HUSMUS9999/squiz-archive/releases), or build from source (Rust 1.85+):

```bash
git clone https://github.com/HUSMUS9999/squiz-archive.git
cd squiz-archive

# Native CPU tuning (AVX2 / AVX-512 / AES-NI)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Cross-compile Windows .exe from Linux (requires mingw-w64)
rustup target add x86_64-pc-windows-gnu
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq" cargo build --release --target x86_64-pc-windows-gnu
```

## Benchmarks

### Single-Core Codec Comparison (8 MiB Real Workloads)

| Codec | CSV Telemetry (8 MiB) | ELF Binaries (8 MiB) | C Headers (4 MiB) |
|---|---|---|---|
| `zstd L9` | 4.20x (68.3 MiB/s) | 2.54x (71.2 MiB/s) | 7.28x (109.1 MiB/s) |
| `zstd L19` | 4.91x (2.1 MiB/s) | 2.79x (4.6 MiB/s) | 8.16x (5.2 MiB/s) |
| `bzip3` (BWT+LZP+CM) | 4.70x (15.5 MiB/s) | 2.79x (13.1 MiB/s) | **8.81x** (20.5 MiB/s) |
| `ppmd` (PPMd7 order 8) | 4.55x (9.8 MiB/s) | 2.79x (7.4 MiB/s) | 8.70x (28.6 MiB/s) |
| `lzma2 L6` | 4.89x (2.5 MiB/s) | 2.96x (3.6 MiB/s) | 8.39x (5.1 MiB/s) |
| `lzma2-bcj L6` (x86) | 4.89x (2.7 MiB/s) | **3.13x** (3.5 MiB/s) | 8.39x (4.8 MiB/s) |

### 3-Node Cluster Testbed (Shared 5 GHz Wireless LAN, `AES-256-GCM` Enabled)

- Coordinator: Windows x86_64, 6C/12T (2.6 GHz), 16 GiB RAM (10T compute, 2T reserved for I/O)
- Worker 1: Linux x86_64, 16C/32T (2.5-5.4 GHz), 30 GiB RAM
- Worker 2: Linux x86_64, 12C/20T (2.1-4.9 GHz), 62 GiB RAM

| Workload | Preset / Codec | Local (12T) | Cluster (62T) | Speedup | Ratio |
|---|---|---|---|---:|---:|
| 256 MiB CSV dataset | `zstd L19` (8M blk) | 8.3 MiB/s | 23.3 MiB/s | 2.81x | 4.94x |
| 256 MiB CSV dataset | `lzma2 L6` (8M blk) | 10.9 MiB/s | 28.8 MiB/s | 2.65x | 4.92x |
| 256 MiB mixed-entropy | `zstd L19` (2M blk) | 12.0 MiB/s | 35.1 MiB/s | 2.91x | 3.69x |
| 128 MiB PE binaries | `lzma2 L6` (2M blk) | 22.9 MiB/s | 39.6 MiB/s | 1.73x | 3.38x |
| 1.25 GiB directory (23k files) | `zstd L12` (`.sqz`) | - | 90.6 s (312 MiB out) | - | 4.11x |
| 185.5 GiB CSV dataset (107 files) | `zstd L9` (`.sqz`, 8M) | - | 2748 s (45.2 GiB out, 69.1 MiB/s) | - | 4.10x |
| 256 MiB parallel decompress | `zstd` (`auto`) | 0.10 s (2566 MiB/s) | 0.12 s (2108 MiB/s) | 0.83x* | - |

*\*In `auto` mode, fast Zstd decompression stays local because local decode throughput exceeds wireless RX bandwidth; the 20 ms delta is cluster setup overhead.*

## Documentation

- [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md): Codec selection guide, per-slab auto-routing, and empirical trade-offs
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): Pipeline design, `.sqz` v3 binary format, wire protocol, and security model
- [`docs/CLUSTER_SETUP.md`](docs/CLUSTER_SETUP.md): LAN, Tailscale/WireGuard, cloud deployment (`systemd`, Windows Task), and OS TCP tuning scripts (`scripts/`)
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md): Complete command, preset, natural-language, and flag reference
- [`CHANGELOG.md`](CHANGELOG.md): Release history

## License

MIT. See [LICENSE](LICENSE).
