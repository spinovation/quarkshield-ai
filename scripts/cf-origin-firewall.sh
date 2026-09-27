#!/usr/bin/env bash
#
# cf-origin-firewall.sh — Lock the origin's Docker-published web ports to Cloudflare.
#
# QuarkShield publishes ports 80/443/5050 directly from Docker (no host nginx),
# so the origin IP is reachable directly, bypassing Cloudflare's WAF/DDoS. This
# script restricts those ports to Cloudflare's published IP ranges (IPv4 + IPv6)
# using the DOCKER-USER chain — the only correct place, because Docker's
# published-port traffic traverses DOCKER-USER, NOT the INPUT chain.
#
# SSH SAFETY: SSH (port 22) is a normal host service on the INPUT chain, which
# this script never touches. You CANNOT be locked out of SSH by this script.
#
# Usage:
#   sudo ./cf-origin-firewall.sh apply     # fetch CF ranges and apply rules
#   sudo ./cf-origin-firewall.sh status    # show the current cf-origin rules
#   sudo ./cf-origin-firewall.sh remove    # remove all cf-origin rules (rollback)
#   sudo ./cf-origin-firewall.sh persist   # install a systemd unit to re-apply on boot/docker restart
#
# Env overrides:
#   RESTRICTED_PORTS   default "80,443,5050"  (comma list, no spaces)
#   WAN_IF             default = the default-route interface (auto-detected)
#
set -euo pipefail

RESTRICTED_PORTS="${RESTRICTED_PORTS:-80,443,5050}"
MARK="cf-origin"
WAN_IF="${WAN_IF:-$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
: "${WAN_IF:=eth0}"

CF4_URL="https://www.cloudflare.com/ips-v4"
CF6_URL="https://www.cloudflare.com/ips-v6"

log() { printf '  %s\n' "$*"; }

require_root() { [ "$(id -u)" -eq 0 ] || { echo "Must run as root (use sudo)."; exit 1; }; }

# Remove any rules we previously added (matched by our comment marker), for one table.
_purge() {
  local IPT="$1"
  $IPT -S DOCKER-USER 2>/dev/null | grep -- "$MARK" | sed 's/^-A/-D/' | while read -r rule; do
    # shellcheck disable=SC2086
    $IPT $rule 2>/dev/null || true
  done
}

# Apply rules for one table ($1=iptables|ip6tables, $2=space-separated CIDR list).
_apply_table() {
  local IPT="$1"; local LIST="$2"
  if ! $IPT -L DOCKER-USER >/dev/null 2>&1; then
    log "$IPT: DOCKER-USER chain not found (is Docker running?) — skipping."
    return 0
  fi
  _purge "$IPT"

  # Insert order matters. We -I (insert at top) so the final top-to-bottom order is:
  #   1) allow ESTABLISHED,RELATED   2) allow each Cloudflare CIDR   3) DROP the rest
  # ...all ABOVE Docker's own trailing RETURN in DOCKER-USER.

  # 3) DROP everything else to the restricted ports arriving on the WAN interface.
  $IPT -I DOCKER-USER -i "$WAN_IF" -p tcp -m multiport --dports "$RESTRICTED_PORTS" \
    -m comment --comment "$MARK" -j DROP

  # 2) Allow each Cloudflare range (inserted above the DROP).
  local cidr
  for cidr in $LIST; do
    [ -n "$cidr" ] || continue
    $IPT -I DOCKER-USER -i "$WAN_IF" -s "$cidr" -p tcp -m multiport --dports "$RESTRICTED_PORTS" \
      -m comment --comment "$MARK" -j RETURN
  done

  # 1) Allow already-established connections (inserted at the very top).
  $IPT -I DOCKER-USER -i "$WAN_IF" -p tcp -m multiport --dports "$RESTRICTED_PORTS" \
    -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$MARK" -j RETURN

  log "$IPT: applied $(echo "$LIST" | wc -w) Cloudflare ranges on $WAN_IF for ports $RESTRICTED_PORTS."
}

cmd_apply() {
  require_root
  command -v curl >/dev/null || { echo "curl is required."; exit 1; }
  log "Fetching Cloudflare IP ranges..."
  local CF4 CF6
  CF4="$(curl -fsSL --max-time 20 "$CF4_URL")" || { echo "Failed to fetch $CF4_URL"; exit 1; }
  CF6="$(curl -fsSL --max-time 20 "$CF6_URL")" || { echo "Failed to fetch $CF6_URL"; exit 1; }
  # Sanity-check the payloads look like CIDR lists before we touch the firewall.
  echo "$CF4" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' || { echo "CF IPv4 list looks malformed; aborting."; exit 1; }
  echo "$CF6" | grep -qiE '^[0-9a-f:]+/[0-9]+$'                     || { echo "CF IPv6 list looks malformed; aborting."; exit 1; }
  log "Interface: $WAN_IF   Ports: $RESTRICTED_PORTS"
  _apply_table iptables  "$CF4"
  _apply_table ip6tables "$CF6"
  echo
  log "Done. Verify NOW (before closing this session):"
  log "  1) The site still loads via Cloudflare:  https://quarkshield.ai/health"
  log "  2) Direct origin is blocked:  curl --max-time 5 http://<ORIGIN_IP>/  (should hang/refuse)"
  log "  3) SSH is unaffected (this chain does not touch port 22)."
  log "Rollback if anything is wrong:  sudo $0 remove"
}

cmd_status() {
  echo "== iptables DOCKER-USER (cf-origin rules) =="; iptables -S DOCKER-USER 2>/dev/null | grep -- "$MARK" || echo "  (none)"
  echo "== ip6tables DOCKER-USER (cf-origin rules) =="; ip6tables -S DOCKER-USER 2>/dev/null | grep -- "$MARK" || echo "  (none)"
}

cmd_remove() {
  require_root
  _purge iptables
  _purge ip6tables
  log "Removed all $MARK rules from DOCKER-USER (v4 + v6)."
}

# Optional: re-apply automatically on boot / after Docker restarts (Docker can
# reset DOCKER-USER). Installs a oneshot systemd unit + a path/timer refresh.
cmd_persist() {
  require_root
  local script_path; script_path="$(readlink -f "$0")"
  cat > /etc/systemd/system/cf-origin-firewall.service <<UNIT
[Unit]
Description=Restrict Docker-published web ports to Cloudflare (cf-origin)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${script_path} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable cf-origin-firewall.service >/dev/null 2>&1 || true
  log "Installed cf-origin-firewall.service (runs '${script_path} apply' after docker on boot)."
  log "It also refreshes the Cloudflare ranges each boot. Re-run 'apply' manually to refresh sooner."
}

case "${1:-}" in
  apply)   cmd_apply ;;
  status)  cmd_status ;;
  remove)  cmd_remove ;;
  persist) cmd_persist ;;
  *) echo "Usage: sudo $0 {apply|status|remove|persist}"; exit 1 ;;
esac
