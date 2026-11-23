#!/usr/bin/env bash
set -euo pipefail

ORIG_ARGS=("$@")
PERSIST=0
STATUS_ONLY=0
REVERT=0
JUMBO_IF=""
WIFI_IF=""

SYSCTL_CONF="/etc/sysctl.d/99-squiz-archive.conf"
MODULES_CONF="/etc/modules-load.d/99-squiz-archive.conf"
NM_CONF="/etc/NetworkManager/conf.d/99-squiz-wifi-powersave.conf"

usage() {
  cat <<'EOF'
Usage: tune-linux.sh [OPTIONS]

Configure Linux TCP stack parameters (BBR, fq, 16 MiB autotuning buffers) for squiz-archive.

Options:
  --persist          Persist sysctl settings, kernel modules, and NM Wi-Fi config across reboots
  --jumbo <iface>    Set MTU 9000 on a wired Ethernet interface (runtime only; requires switch support)
  --wifi <iface>     Disable Wi-Fi power_save on a wireless interface
  --revert           Remove persisted drop-in configs and reload sysctl/NetworkManager
  --status           Print current kernel TCP settings (no root required)
  -h, --help         Show this help
EOF
}

find_bin() {
  local name="$1"
  PATH="$PATH:/usr/sbin:/sbin" command -v "$name" 2>/dev/null || true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --persist) PERSIST=1; shift ;;
    --status) STATUS_ONLY=1; shift ;;
    --revert) REVERT=1; shift ;;
    --jumbo)
      [[ $# -ge 2 && -n "${2:-}" ]] || { echo "Error: --jumbo requires an interface name" >&2; exit 1; }
      JUMBO_IF="$2"; shift 2
      ;;
    --wifi)
      [[ $# -ge 2 && -n "${2:-}" ]] || { echo "Error: --wifi requires an interface name" >&2; exit 1; }
      WIFI_IF="$2"; shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Error: unknown argument '$1'" >&2; usage >&2; exit 1 ;;
  esac
done

SYSCTL_BIN="$(find_bin sysctl)"
MODPROBE_BIN="$(find_bin modprobe)"
IP_BIN="$(find_bin ip)"
IW_BIN="$(find_bin iw)"

if [[ -z "$SYSCTL_BIN" ]]; then
  echo "Error: sysctl not found in PATH, /usr/sbin, or /sbin" >&2
  exit 1
fi

show_status() {
  "$SYSCTL_BIN" \
    net.core.default_qdisc \
    net.ipv4.tcp_congestion_control \
    net.core.rmem_max \
    net.core.wmem_max \
    net.ipv4.tcp_rmem \
    net.ipv4.tcp_wmem \
    net.ipv4.tcp_slow_start_after_idle \
    net.ipv4.tcp_mtu_probing \
    net.ipv4.tcp_notsent_lowat 2>/dev/null || true
}

if [[ "$STATUS_ONLY" -eq 1 ]]; then
  show_status
  exit 0
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root: sudo $0 ${ORIG_ARGS[*]:-}" >&2
  exit 1
fi

if [[ "$REVERT" -eq 1 ]]; then
  rm -f "$SYSCTL_CONF" "$MODULES_CONF" "$NM_CONF"
  "$SYSCTL_BIN" --system >/dev/null 2>&1 || true
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    systemctl reload NetworkManager || true
  fi
  echo "Removed persisted squiz-archive tuning files. Reboot or restore runtime MTU/sysctl values if needed."
  exit 0
fi

if [[ -n "$MODPROBE_BIN" ]]; then
  "$MODPROBE_BIN" tcp_bbr 2>/dev/null || echo "Warning: could not load tcp_bbr module" >&2
  "$MODPROBE_BIN" sch_fq 2>/dev/null || echo "Warning: could not load sch_fq module" >&2
fi

SETTINGS=(
  "net.core.default_qdisc=fq"
  "net.ipv4.tcp_congestion_control=bbr"
  "net.core.rmem_max=16777216"
  "net.core.wmem_max=16777216"
  "net.ipv4.tcp_rmem=4096 262144 16777216"
  "net.ipv4.tcp_wmem=4096 262144 16777216"
  "net.ipv4.tcp_slow_start_after_idle=0"
  "net.ipv4.tcp_mtu_probing=1"
  "net.ipv4.tcp_notsent_lowat=131072"
)

for kv in "${SETTINGS[@]}"; do
  if ! "$SYSCTL_BIN" -w "$kv" >/dev/null 2>&1; then
    echo "Warning: failed to set $kv" >&2
  fi
done

if [[ "$PERSIST" -eq 1 ]]; then
  mkdir -p /etc/sysctl.d /etc/modules-load.d
  printf "%s\n" "${SETTINGS[@]}" > "$SYSCTL_CONF"
  printf "tcp_bbr\nsch_fq\n" > "$MODULES_CONF"
  echo "Persisted sysctl to $SYSCTL_CONF and modules to $MODULES_CONF"
fi

if [[ -n "$JUMBO_IF" ]]; then
  if [[ -z "$IP_BIN" ]]; then
    echo "Error: ip command not found; cannot set MTU on $JUMBO_IF" >&2
    exit 1
  fi
  if ! "$IP_BIN" link show dev "$JUMBO_IF" >/dev/null 2>&1; then
    echo "Error: interface '$JUMBO_IF' does not exist" >&2
    exit 1
  fi
  "$IP_BIN" link set dev "$JUMBO_IF" mtu 9000
  echo "Set runtime MTU 9000 on $JUMBO_IF (requires end-to-end MTU 9000 on switch and peers)."
fi

if [[ -n "$WIFI_IF" ]]; then
  if [[ -n "$IW_BIN" ]] && "$IW_BIN" dev "$WIFI_IF" set power_save off 2>/dev/null; then
    echo "Disabled Wi-Fi power_save on $WIFI_IF"
  else
    echo "Warning: could not disable power_save on '$WIFI_IF' (iw missing or unsupported driver)" >&2
  fi
  if [[ "$PERSIST" -eq 1 && -d /etc/NetworkManager/conf.d ]]; then
    printf "[connection]\nwifi.powersave = 2\n" > "$NM_CONF"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl reload NetworkManager 2>/dev/null || true
    fi
    echo "Persisted NetworkManager config to $NM_CONF"
  fi
fi

echo "Current Linux TCP settings:"
show_status
