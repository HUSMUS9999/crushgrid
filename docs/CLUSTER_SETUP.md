# Cluster Setup Guide — LAN, Tailscale/WireGuard, and Public Internet / Cloud

`squiz-archive` scales horizontally to **as many devices as you choose** (2, 5, 20, or 100+ nodes) across any mix of **Linux, Windows, and macOS** machines on LAN, VPN meshes, or cloud providers.

Every machine runs the **same single binary** (`squiz-archive` / `squiz-archive.exe`):
- Machines contributing spare CPU/RAM run **`squiz-archive worker`**
- The machine holding the data runs **`squiz-archive pack` / `compress` / `unpack` / `decompress`** (or any machine can coordinate!)

---

## Step 1: Generate a Strong Shared Cluster Token

All workers and the coordinator authenticate mutually using a shared secret (`BLAKE3` keyed challenge-response with 32-byte OS CSPRNG nonces + per-session derived 256-bit `AES-256-GCM` keys):

```bash
# Linux / macOS
openssl rand -hex 32

# Windows PowerShell
-join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) })
```

Export it as `SQUIZ_TOKEN` or place it in a `cluster.conf` file with restricted permissions (`chmod 600 cluster.conf`).

---

## Scenario A: Local Area Network (LAN — Wi-Fi / Gigabit / 2.5GbE / 10GbE)

### 1. Start Workers on Every Participating Machine
```bash
# Linux / macOS worker (hard resource guardrails cannot be exceeded by any coordinator)
squiz-archive worker --bind 0.0.0.0:7878 --token "$SQUIZ_TOKEN" --max-threads 32 --max-mem 8G
```
```powershell
# Windows worker
.\squiz-archive.exe worker --bind 0.0.0.0:7878 --token "$env:SQUIZ_TOKEN" --max-threads 12 --max-mem 4G
```

### 2. Open Port `7878/TCP` on LAN Firewalls Only
- **Linux (`ufw`):**
  ```bash
  sudo ufw allow from 192.168.0.0/16 to any port 7878 proto tcp
  ```
- **Windows (Admin PowerShell):**
  ```powershell
  New-NetFirewallRule -DisplayName "squiz-archive LAN" -Direction Inbound -Protocol TCP -LocalPort 7878 -RemoteAddress LocalSubnet -Action Allow
  ```
- **macOS:** Allow incoming connections when prompted or add `squiz-archive` in *System Settings → Network → Firewall*.

### 3. Verify All Nodes & Run
```bash
cp cluster.conf.example cluster.conf
# Edit cluster.conf with your LAN IPs & token
squiz-archive probe --cluster cluster.conf

# Interactive picker (-i / --pick) lets you toggle any subset of nodes and tune threads/RAM live:
squiz-archive pack /path/to/folder -o backup.sqz --cluster cluster.conf --pick
```

---

## Scenario B: Over the Internet via Tailscale / WireGuard Mesh (Recommended!)

If your machines are in different homes, offices, or cloud regions behind NAT/CGNAT routers, **Tailscale** or **WireGuard** connects them directly peer-to-peer with **zero router port-forwarding** and automatic NAT traversal.

1. Install [Tailscale](https://tailscale.com) (or WireGuard) on every machine (home PCs, laptops, cloud VMs).
2. Bind workers strictly to the VPN interface IP (never exposed to the public Internet!):
   ```bash
   # Find your Tailscale IP (e.g. 100.x.y.z)
   TS_IP=$(tailscale ip -4)
   squiz-archive worker --bind "${TS_IP}:7878" --token "$SQUIZ_TOKEN" --max-threads 24 --max-mem 16G --allow-auth-only
   ```
3. Add all Tailscale IPs to `cluster.conf`:
   ```ini
   token = YOUR_64_CHAR_HEX_TOKEN
   security = auth-only   # WireGuard already encrypts packets; or keep `aead` for defense-in-depth
   wire_codec = zstd1     # Shrinks slabs before crossing WAN links
   streams = 4            # Higher parallelism hides WAN RTT

   node = local:threads=auto,mem=4G
   node = 100.64.0.10:7878:threads=max,mem=16G
   node = 100.64.0.11:7878:threads=max,mem=32G
   node = 100.64.0.12:7878:threads=16,mem=8G
   ```
4. Probe & compress across all nodes:
   ```bash
   squiz-archive probe --cluster cluster.conf
   squiz-archive pack ./dataset -o dataset.sqz --cluster cluster.conf --codec zstd --level 15
   ```

---

## Scenario C: Direct Over the Public Internet (Cloud VMs: AWS, Hetzner, GCP, DigitalOcean, VPS)

You can spin up cheap spot/preemptible 32–128 vCPU cloud workers across any provider and pool them with your local PC!

### Security Checklist for Public Internet Workers
1. **ALWAYS enforce AEAD encryption** — do **NOT** pass `--allow-auth-only` on public-facing workers! By default `squiz-archive worker` rejects any unencrypted connection (`AES-256-GCM` with per-session derived keys + header AAD is mandatory).
2. **Restrict port `7878/TCP` to your coordinator's public IP** in your cloud Security Group / firewall:
   ```bash
   # Example on Ubuntu/Debian cloud VM (replace YOUR_PUBLIC_IP)
   sudo ufw allow from YOUR_PUBLIC_IP/32 to any port 7878 proto tcp
   ```
3. **Use a 256-bit random token** (`openssl rand -hex 32`) passed via `SQUIZ_TOKEN` env var or `chmod 600` config file (avoid putting secrets in shell history).
4. **Tune WAN Parameters in `cluster.conf`:**
   - Use `wire_codec = zstd1` (saves 60–90% of WAN upload bandwidth on text/code/CSV/logs!)
   - Use `streams = 4` to `8` on 30–150 ms WAN links to fill the Bandwidth-Delay Product (BDP)
   - Use `bw = 50M` (optional) if you want to cap uplink usage so your home/office internet stays responsive
   - Use `--codec zstd --level 15..22` or `--codec lzma2 --level 6..9` so CPU work per megabyte easily outweighs WAN transfer time!

### Running Workers as Persistent Background Services

#### Linux `systemd` (`/etc/systemd/system/squiz-worker.service`)
```ini
[Unit]
Description=squiz-archive distributed compression worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="SQUIZ_TOKEN=REPLACE_WITH_YOUR_64_CHAR_HEX_TOKEN"
ExecStart=/usr/local/bin/squiz-archive worker --bind 0.0.0.0:7878 --max-threads 32 --max-mem 16G
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now squiz-worker
sudo journalctl -u squiz-worker -f
```

#### Windows Background Worker (Admin PowerShell)
```powershell
$action = New-ScheduledTaskAction -Execute "C:\squiz-archive\squiz-archive.exe" `
  -Argument 'worker --bind 0.0.0.0:7878 --token "YOUR_TOKEN" --max-threads 10 --max-mem 4G'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "SquizArchiveWorker" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
Start-ScheduledTask -TaskName "SquizArchiveWorker"
```

---

## Performance Tuning Tips (Wi-Fi, Wired LAN, & Cloud)

| Transport | Recommended Settings | Expected Scaling |
|---|---|---|
| **Wi-Fi 5 / Wi-Fi 6** | `--wire-codec auto` (`zstd1`), `--streams 2..3`, disable Wi-Fi `power_save` / `SMPS`, keep `AC_BE` (`IP_TOS=0x00`), enable Linux BBR | **2×–4×** on high ratios (`zstd L15-22`, `lzma2`, CSV/logs/code) |
| **Wired 1GbE / 2.5GbE / 10GbE** | Enable **Jumbo Frames (`MTU 9000`)** on all NICs & switch, `--wire-codec auto` (`lz4`), `--streams 4`, Linux BBR + 16 MiB `tcp_rmem`/`tcp_wmem` | **4×–10×+** near-linear scaling across N nodes |
| **Internet / Cloud WAN** | `--security aead`, `--wire-codec zstd1`, `--streams 4..8`, high levels (`zstd L15-22` or `lzma2 L6-9`), optional `bw=` cap | Near-linear scaling for CPU-heavy & high-compressibility workloads |

Verify your real link speed before running big jobs:
```bash
squiz-archive net-bench --cluster cluster.conf --streams 4 --mib 32
```
