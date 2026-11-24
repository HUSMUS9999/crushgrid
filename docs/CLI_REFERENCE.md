# CLI Reference

Run `crushgrid -h` or `crushgrid <subcommand> -h` for live help.

## Subcommands

| Command | Aliases | Description |
|---|---|---|
| `do "<text>"` | `ask` | Translate a natural-language request into CLI flags and execute it (`--dry-run` to preview only) |
| `init` | - | Setup wizard that generates a 256-bit CSPRNG token and `0600` `cluster.conf` (`--force` to overwrite) |
| `doctor` | - | Inspect local CPU, RAM, auto-detected `cluster.conf`, built-in codecs, and OS TCP stack |
| `worker` | - | Run a compute worker daemon with hard `--max-threads` and `--max-mem` ceilings |
| `probe` | - | Probe reachability, CPU/RAM ceilings, RTT, and burst link throughput for configured nodes |
| `pack <src>` | `archive`, `zip` | Pack a directory or file tree into a deduplicated, multi-codec `.sqz` archive |
| `unpack <arc>` | `extract`, `unzip` | Extract a `.sqz` directory archive in parallel via positional writes |
| `inspect <arc>` | - | Display format, ratio, per-codec slab breakdown, dedup/raw-bypass stats, and optional file list (`--list`, first 100 entries) |
| `compress <file>` | - | Compress a single file into seekable `.zst` or `.sqz` |
| `decompress <arc>` | - | Decompress a seekable `.zst` or `.sqz` file in parallel (`--no-verify` skips whole-file BLAKE3 check) |
| `bench <file>` | - | Run local-only vs cluster compress/decompress benchmark with BLAKE3 verification |
| `net-bench` | - | Measure raw multi-stream bidirectional TCP + AEAD wire throughput to remote workers |

## Common Flags

| Flag | Commands | Default | Description |
|---|---|---|---|
| `-m, --preset` | `pack`, `compress`, `bench` | `balanced` | `fast`, `balanced`, `small`, or `max` |
| `--codec` | `pack`, `compress`, `bench` | preset default | `auto`, `zstd`, `bzip3`, `ppmd`, `lzma2`, `lzma2-bcj`, `lz4` |
| `-l, --level` | `pack`, `compress`, `bench` | codec default | `zstd`: `1..22`, `lzma2`/`bcj`: `0..9`, `bzip3`: `1..32` MiB, `ppmd`: `4..12` |
| `--format` | `compress` | `auto` | `auto` (`.zst` for single-codec Zstd, `.sqz` otherwise), `zst`, or `sqz` |
| `--block-size` | `pack`, `compress`, `bench` | `auto` | Slab size (`64K..32M`, e.g. `4M`, `8M`, `16M`) or `auto` |
| `--exclude` | `pack` | none | Top-level folder or file name to exclude (repeatable) |
| `--no-dedup` | `pack`, `compress` | `false` | Disable `BLAKE3` exact slab deduplication (`.sqz` only) |
| `--no-raw-bypass` | `pack`, `compress` | `false` | Disable zero-CPU incompressible slab bypass (`.sqz` only) |
| `--cluster` | cluster commands | auto user/sys | Path to `cluster.conf` (required for CWD `./cluster.conf`) |
| `--local` | cluster commands | `false` | Ignore saved `cluster.conf` and run locally (preserves `--node local:...`) |
| `--node` / `--nodes` | cluster commands | `local` | Explicit node allocation specs (repeatable or comma-separated) |
| `-i, --pick` | `pack`, `unpack`, `compress`, `decompress` | `false` | Interactive device and resource picker |
| `--mem-limit` | cluster commands | auto | Coordinator RAM ceiling (default: 1/3 available RAM, clamped `256M..4G`) |
| `--security` | cluster commands | `aead` | `aead` (`AES-256-GCM`, default) or `auth-only` (WireGuard/Tailscale) |
| `--schedule` | `pack`, `unpack`, `compress`, `decompress` | `auto` | `auto` (cost-aware), `force-all`, or `local-only` |
| `--wire-codec` | `pack`, `unpack`, `compress`, `decompress`, `bench` | `auto` | `auto` (`zstd1` <100 MiB/s, `lz4` >=100 MiB/s), `zstd1`, `lz4`, or `none` |
| `--streams` | cluster commands | `2` (`4` net-bench) | Parallel TCP streams per remote worker (`1..=8`) |
| `--no-hedge` | `pack`, `unpack`, `compress`, `decompress` | `false` | Disable tail speculative hedging |
| `--max-threads` | `worker` | all threads | Hard server-side CPU thread ceiling |
| `--max-mem` | `worker` | `4G` | Hard server-side buffer memory ceiling |
| `--allow-auth-only` | `worker` | `false` | Permit `--security auth-only` clients (never set on public Internet workers) |

## Auto-Discovery & Smart Defaults

- **Cluster config discovery:** If none of `--cluster`, `--node`, `--nodes`, or `--local` are passed, `crushgrid` checks only trusted user/system locations (never CWD `./cluster.conf`, preventing untrusted-directory exfiltration):
  1. `$XDG_CONFIG_HOME/crushgrid/cluster.conf` (Unix)
  2. `~/.config/crushgrid/cluster.conf` (Unix) / `%APPDATA%\crushgrid\cluster.conf` (Windows)
  3. `/etc/crushgrid/cluster.conf` (Unix)
  Pass `--cluster ./cluster.conf` explicitly to use a config file in the current directory.
- **Optional output paths (`-o`):** Omitting `-o` derives `<source>.sqz` for `pack`, `<input>.zst`/`.sqz` for `compress`, and `<archive-stem>` for `unpack`/`decompress`.
- **Coordinator I/O reservation:** When `threads=auto` is used with remote workers active, 1-2 local logical threads are reserved for TCP/AEAD/disk I/O.

## Node Allocation Grammar (`--node` / `cluster.conf`)

Format: `<target>[:key=value,key=value,...]`

- `<target>`: `local`, `host:port`, or `host` (defaults to port `7878`)
- `threads=` (aliases `t=`, `cpu=`): `auto`, `max`, exact count (`16`), or percentage (`75%`)
- `mem=` (aliases `ram=`, `memory=`): byte size (`512M`, `4G`)
- `bw=` (alias `bandwidth=`): coordinator TX cap in **bytes/sec** (`10M` = 10 MiB/s ≈ 84 Mbps)
- `streams=` (alias `s=`): parallel TCP streams per peer (`1..=8`)

## Natural-Language Mode (`crushgrid do`)

`crushgrid do` parses natural language offline without external APIs and always prints the exact command before executing. Use `--dry-run` to preview:

```bash
crushgrid do --dry-run "compress ./backups as small as possible using 50% cpu and 2G ram"
crushgrid do "fast backup of ./logs locally"
crushgrid do "extract backups.sqz into ./restored"
crushgrid do "decompress file.sqz into file.bin"
crushgrid do "inspect backups.sqz and list files"
crushgrid do "check cluster nodes"
```

## Environment Variables

- `CRUSHGRID_TOKEN`: Shared cluster authentication token (preferred over `--token` CLI flag to keep secrets out of process lists and shell history).
