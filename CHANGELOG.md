# Changelog

All notable changes to `crushgrid` (formerly `squiz-archive`) follow Semantic Versioning (`MAJOR.MINOR.PATCH`).

## [1.1.0] - 2026-11-24

### Changed
- Rebranded CLI and package from `squiz-archive` to **`crushgrid`** (`CRUSHGRID_TOKEN`, `~/.config/crushgrid/cluster.conf`) while keeping 100% `.sqz` archive format compatibility, wire-protocol PSK compatibility, and automatic fallback discovery for legacy `~/.config/squiz-archive/cluster.conf`.
- Added adaptive Light/Dark fine-line SVG hero, compact self-hosted badges, Features-first README, and unbiased single-host benchmarks against `tar+gzip`, `tar+bzip2`, `tar+zstd`, and `tar+xz`.

## [1.0.0] - 2026-11-24

### Added
- Complete documentation suite: `docs/ALGORITHMS.md`, `docs/ARCHITECTURE.md`, `docs/CLI_REFERENCE.md`, `docs/CLUSTER_SETUP.md`, and `CHANGELOG.md`.
- Unit and integration test suite (`cargo test`) covering all 6 codecs (1 B to 100 KiB + incompressible), OOM header rejection, path-traversal defense, `.sqz` v3 multi-codec `pack`/`unpack`, natural-language parser edge cases, AEAD handshake/auth, and config parsing.
- Flattened `ClusterArgs` so every CLI flag across all subcommands includes help documentation in `-h`.
- `init --force` flag to prevent accidental overwrite of an existing `cluster.conf`.

### Security
- Enforced 64 MiB hard bounds checks on PPMd7 `mem_size`, Bzip3 header block size, and worker `JobReq.orig_len` before memory allocation, plus file-bounds and 256 MiB cap checks on `.sqz` seek tables and manifests.
- Removed CWD `./cluster.conf` from implicit config auto-discovery to prevent untrusted-directory data redirection (explicit `--cluster ./cluster.conf` still supported).
- Created `cluster.conf` atomically with `0600` mode on Unix (`OpenOptionsExt::mode`) to eliminate TOCTOU permission windows during `init`.

### Fixed
- Fixed `squiz-archive do` parsing of `"as small as possible"` / `"to maximum"` (no longer misparsed as `-o possible`), filename keyword collisions (`audit.log`), `"big ram"` validation, `"decompress foo.sqz"` routing, and quoted paths with spaces.
- Preserved explicit `--node local:...` thread/RAM overrides when `--local` is passed.
- Added per-chunk retry cap (`MAX_CHUNK_RETRIES = 3`) on remote `MsgType::Error` to prevent infinite re-queue loops on corrupt slabs.
- Extended `classify_slab_content` to recognize multi-byte UTF-8 text (not just ASCII) and made `select_active_nodes` inspect actual per-slab codecs on extraction.

## [0.8.0] - 2026-11-24

### Added
- Offline natural-language CLI abstraction (`squiz-archive do "<request>"`, alias `ask`) with `--dry-run` preview.
- `squiz-archive init` setup wizard generating 256-bit OS CSPRNG tokens and `0600` `cluster.conf` files.
- `squiz-archive doctor` system, config, and OS TCP stack diagnostics.
- Automatic user/system `cluster.conf` discovery plus `--local` override.
- Device-aware default `--mem-limit` (1/3 available RAM, clamped to `256 MiB..4 GiB`).
- Optional `-o` output paths across `pack`, `unpack`, `compress`, and `decompress`, plus command aliases (`archive`/`zip`, `extract`/`unzip`).

## [0.7.0] - 2026-11-24

### Added
- Three new empirically validated codec families: `bzip3` (BWT+LZP+CM, statically bundled `libbzip3`), `ppmd` (PPMd7, pure Rust), and `lzma2-bcj` (x86 BCJ filter + LZMA2).
- `.sqz` v3 container with per-slab 1-byte codec IDs (zero header overhead, backwards-compatible with v1/v2).
- Fast `<0.05 ms` content classifier and human-friendly presets (`-m` / `--preset fast|balanced|small|max`) with automatic per-slab multi-codec routing (`--codec auto`).
- Per-codec slab breakdown in `squiz-archive inspect`.

## [0.6.2] - 2026-11-23

### Security & Fixes
- Moved `WorkerCaps` out of unauthenticated `HelloServer` into encrypted `AuthOk` to prevent pre-auth host metadata disclosure.
- Switched constant-time MAC check to `blake3::Hash` equality (`constant_time_eq`).
- Added hardened one-command OS tuning scripts (`scripts/tune-linux.sh`, `scripts/tune-windows.ps1`) with `--revert`/`-Revert` and `--status`/`-Status`.
- Fixed `decompress --no-verify` toggle and added singular `--node` to `net-bench`.

## [0.6.1] - 2026-11-23

### Added
- N-node `--cluster <file>` configuration support (`cluster.conf.example`) and `docs/CLUSTER_SETUP.md`.
- 3-second connect timeout during cluster probing so offline nodes never stall discovery.

## [0.6.0] - 2026-11-23

### Added
- Initial public release of `squiz-archive` with pull-based work stealing, `AES-256-GCM` framing, Zstd LDM, LZMA2, LZ4, `BLAKE3` slab dedup, entropy raw bypass, directory `pack`/`unpack`/`inspect`, adaptive wire pre-shrink (`zstd1`/`lz4`), airtime-weighted AIMD credits, roaming re-queue, and `net-bench`.
