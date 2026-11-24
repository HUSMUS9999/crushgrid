# Cluster Setup Guide

`squiz-archive` scales to as many nodes as you configure (LAN, WireGuard/Tailscale, or cloud instances) across Linux, Windows, and macOS.

Every node runs the same executable:
- Contributing hosts run `squiz-archive worker`
- The host holding the source files runs `squiz-archive pack`, `compress`, `unpack`, or `decompress`

## 1. Generate a Shared Cluster Token

The fastest way to create a `0600` `cluster.conf` with a 256-bit OS CSPRNG token is `squiz-archive init --nodes <host1:7878,host2:7878>`. To generate a token manually:

All connections perform mutual `BLAKE3` challenge-response authentication using a pre-shared token and 32-byte OS CSPRNG nonces, deriving a per-session 256-bit `AES-256-GCM` key (note: PSK derivation does not provide forward secrecy; rotate tokens periodically or run over WireGuard/Tailscale).

```bash
# Linux / macOS
openssl rand -hex 32
```

```powershell
# Windows PowerShell (5.1 and 7+, cryptographically secure)
$b = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
($b | ForEach-Object { $_.ToString("x2") }) -join ""
```

Pass the secret via `SQUIZ_TOKEN` in the environment or in a `chmod 600` `cluster.conf` file. Avoid passing `--token` on the command line, which exposes the token in process listings and shell history.

## 2. LAN Deployment (Ethernet or Wi-Fi)

### Start workers

```bash
# Linux / macOS
export SQUIZ_TOKEN="<64-hex-char-token>"
squiz-archive worker --bind 0.0.0.0:7878 --max-threads 16 --max-mem 8G
```

```powershell
# Windows PowerShell
$env:SQUIZ_TOKEN = "<64-hex-char-token>"
.\squiz-archive.exe worker --bind 0.0.0.0:7878 --max-threads 10 --max-mem 4G
```

### Firewall rules (LAN subnet only)

```bash
# Linux (ufw)
sudo ufw allow from 192.168.0.0/16 to any port 7878 proto tcp
```

```powershell
# Windows (Admin PowerShell)
powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Firewall -Port 7878
```

## 3. Over the Internet via Tailscale or WireGuard (Recommended)

A WireGuard/Tailscale mesh connects home PCs, remote laptops, and cloud VMs without router port-forwarding or public exposure of port 7878.

1. Install Tailscale or WireGuard on each host.
2. Bind each worker strictly to its VPN interface IP:
   ```bash
   export SQUIZ_TOKEN="<64-hex-char-token>"
   TS_IP=$(tailscale ip -4)
   squiz-archive worker --bind "${TS_IP}:7878" --max-threads 20 --max-mem 16G --allow-auth-only
   ```
3. List all VPN peers in `cluster.conf`:
   ```ini
   token = <64-hex-char-token>
   security = auth-only   # WireGuard already encrypts packets; keep `aead` for defense-in-depth
   wire_codec = zstd1     # Shrinks slabs before traversing WAN links
   streams = 4

   node = local:threads=auto,mem=4G
   node = 100.64.0.10:7878:threads=max,mem=16G
   node = 100.64.0.11:7878:threads=max,mem=32G
   ```

## 4. Direct Over the Public Internet (Cloud VMs)

When connecting to workers on AWS, Hetzner, GCP, DigitalOcean, or VPS providers over the public Internet:

1. **Enforce AEAD encryption:** Never pass `--allow-auth-only` on public-facing workers. Default worker mode rejects unencrypted sessions.
2. **Allowlist coordinator IPs:** Restrict TCP port `7878` in your cloud Security Group or host firewall to your coordinator's public IP:
   ```bash
   sudo ufw allow from YOUR_PUBLIC_IP/32 to any port 7878 proto tcp
   ```
3. **Configure WAN options in `cluster.conf`:**
   - Set `wire_codec = zstd1` to shrink compressible slabs before upload.
   - Set `streams = 4` to `8` (`1..=8` supported) to fill high-RTT WAN Bandwidth-Delay Product.
   - Set per-node `bw=10M` inside a `node = ...` line if you want to cap uplink usage (`bw=` is in **bytes/sec**, so `10M` = 10 MiB/s ≈ 84 Mbps). `bw` is a per-node option, not a top-level config key.
   - Use CPU-heavy presets (`--preset small` / `--preset max`) or explicit codec/level flags (`--codec zstd --level 15..22`, `--codec lzma2 --level 6..9`) so remote compute outweighs WAN latency.

## 5. Persistent Background Services

### Linux (`systemd`)

Store the token in a root-only environment file so it is never readable in the unit file:

```bash
sudo mkdir -p /etc/squiz-archive
sudo install -m 600 /dev/null /etc/squiz-archive/worker.env
printf 'SQUIZ_TOKEN=%s\n' "<64-hex-char-token>" | sudo tee /etc/squiz-archive/worker.env >/dev/null
```

Create `/etc/systemd/system/squiz-worker.service`:

```ini
[Unit]
Description=squiz-archive distributed compression worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=/etc/squiz-archive/worker.env
ExecStart=/usr/local/bin/squiz-archive worker --bind 0.0.0.0:7878 --max-threads 32 --max-mem 16G
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now squiz-worker
sudo journalctl -u squiz-worker -f
```

### Windows (Scheduled Task)

Set `SQUIZ_TOKEN` as a user environment variable for a dedicated service account (avoid storing tokens inline in task arguments or running under `SYSTEM` unless required):

```powershell
[Environment]::SetEnvironmentVariable("SQUIZ_TOKEN", "<64-hex-char-token>", "User")
$action = New-ScheduledTaskAction -Execute "C:\squiz-archive\squiz-archive.exe" `
  -Argument "worker --bind 0.0.0.0:7878 --max-threads 10 --max-mem 4G"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "SquizArchiveWorker" -Action $action -Trigger $trigger
```

## 6. OS Network Tuning Scripts

Optional one-command scripts tune kernel TCP parameters (Linux BBR + `fq` + 16 MiB autotuning, Windows RFC 1323 timestamps + firewall + NIC options). Both support `--status` / `-Status` and `--revert` / `-Revert`.

```bash
# Linux: apply BBR + 16 MiB buffers and persist across reboots
sudo ./scripts/tune-linux.sh --persist

# Wired Ethernet Jumbo Frames (requires MTU 9000 on switch and all peer NICs)
sudo ./scripts/tune-linux.sh --persist --jumbo eth0

# Wireless Linux host: disable Wi-Fi power_save
sudo ./scripts/tune-linux.sh --persist --wifi wlan0

# Revert persisted Linux configs
sudo ./scripts/tune-linux.sh --revert
```

```powershell
# Windows (Admin PowerShell)
powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Firewall
powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Wifi -WifiAdapter "Wi-Fi"
powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Jumbo "Ethernet"
powershell -ExecutionPolicy Bypass -File .\scripts\tune-windows.ps1 -Revert -Firewall
```

Measure live multi-stream wire speed after tuning:

```bash
squiz-archive net-bench --cluster cluster.conf --streams 4 --mib 32
```
