# Compression Algorithms and Presets

`crushgrid` embeds six general-purpose lossless codecs covering distinct algorithmic families, plus a per-slab classifier that automatically routes each block to the best codec inside `.sqz` v3 archives.

## Included Codecs

| Codec (`--codec`) | Family | Level Range (Default) | Strengths |
|---|---|---|---|
| `zstd` | LZ77 + FSE/Huffman + LDM (`libzstd` C/ASM) | `1..=22` (`9`) | Best general speed-to-ratio curve; `.zst` output is compatible with upstream `zstd -d` |
| `bzip3` | BWT + LZP + Context-Modeled Range Coder (`libbzip3` C) | `1..=32` MiB (`8`) | Highest ratio on source code, CSV, logs, JSON, and structured text while running 4-7x faster than `zstd L19` / `lzma2 L6` |
| `ppmd` | PPMd7 Statistical Context Model (`ppmd-rust`) | `4..=12` order (`8`) | High ratio on dense text and markup at ~28 MiB/s per core |
| `lzma2` | LZ77 + Range Coder (`liblzma` C) | `0..=9` (`6`) | Strong general binary and mixed-data compression |
| `lzma2-bcj` | x86 BCJ Branch/Call/Jump filter + LZMA2 (`liblzma` C) | `0..=9` (`6`) | Best ratio on x86/x86-64 executables, DLLs, and shared libraries (+6% to +12% smaller than plain LZMA2/Zstd) |
| `lz4` | Ultra-fast LZ77 (`lz4_flex`) | `1..=12` (`1`) | Multi-GB/s throughput for fast local disks and 10GbE+ links |

### Why Some Algorithms Were Excluded

- **Brotli (`q9`):** Benchmarked against the same 8 MiB CSV, ELF binary, and C header workloads (`4.22x` CSV, `2.66x` ELF, `7.70x` C headers). It was strictly dominated in both ratio and speed by `bzip3` (`4.70x` / `2.79x` / `8.81x`) and `ppmd` (`4.55x` / `2.79x` / `8.70x`), so it was omitted to keep binary size and maintenance surface lean.
- **PAQ8 / cmix:** Extreme memory per thread (several GiB to 32 GiB per core) and sub-100 KiB/s throughput make them impractical for multi-gigabyte distributed archival.

## Per-Slab Multi-Codec Routing (`--preset small` / `--preset max` / `--codec auto`)

In `.sqz` v3 archives, every slab records its own 1-byte codec ID in the seek table (zero extra header overhead). Before dispatching a slab, the coordinator runs three fast (<0.05 ms) passes:

1. **Exact `BLAKE3` slab deduplication:** If an identical slab was already processed, a 0-byte reference entry is recorded with zero CPU and zero network traffic.
2. **Incompressible entropy bypass:** Four 16 KiB slices spread across the slab are probed with LZ4. If total reduction is under 1.5% (already-compressed archives, video, JPEG/PNG, encrypted blobs), the slab is stored verbatim (`raw`) with zero compression CPU and zero wire transfer.
3. **Content classification (`classify_slab_content`):**
   - **Text / Source / CSV / Logs** (>= 88% printable ASCII/UTF-8) -> `bzip3`
   - **x86/x86-64 Executables** (ELF/PE headers or dense x86 relative CALL/JMP opcodes) -> `lzma2-bcj`
   - **General binary / mixed data** -> `lzma2` (L6 in `small`, L9 in `max`) or `zstd` (when `--preset balanced --codec auto` is specified)

During `pack`, directory files are first sorted by `(FileClass, extension, size, path)` so text files, executables, and already-compressed media land in separate solid slabs before classification.

## Empirical Benchmark Reference (Single Core, 8 MiB Slabs)

| Codec | CSV Telemetry (8 MiB) | ELF Binaries (8 MiB) | C Headers (4.02 MiB) |
|---|---|---|---|
| `zstd L9` | 1.90 MiB (4.20x, 68.3 MiB/s) | 3.15 MiB (2.54x, 71.2 MiB/s) | 0.55 MiB (7.28x, 109.1 MiB/s) |
| `zstd L19` | 1.63 MiB (4.91x, 2.1 MiB/s) | 2.87 MiB (2.79x, 4.6 MiB/s) | 0.49 MiB (8.16x, 5.2 MiB/s) |
| `bzip3` (8M) | 1.70 MiB (4.70x, 15.5 MiB/s) | 2.87 MiB (2.79x, 13.1 MiB/s) | **0.46 MiB (8.81x, 20.5 MiB/s)** |
| `ppmd` (order 8) | 1.76 MiB (4.55x, 9.8 MiB/s) | 2.87 MiB (2.79x, 7.4 MiB/s) | 0.46 MiB (8.70x, 28.6 MiB/s) |
| `lzma2 L6` | 1.64 MiB (4.89x, 2.5 MiB/s) | 2.71 MiB (2.96x, 3.6 MiB/s) | 0.48 MiB (8.39x, 5.1 MiB/s) |
| `lzma2-bcj L6` | 1.64 MiB (4.89x, 2.7 MiB/s) | **2.56 MiB (3.13x, 3.5 MiB/s)** | 0.48 MiB (8.39x, 4.8 MiB/s) |
