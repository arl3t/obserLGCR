#!/bin/bash
# ==============================================================================
# obserLGCR — Agente NOC para Linux
# Plataforma: Linux / Ubuntu / Debian / RHEL / ARM64 / x86_64
# Requiere: curl, jq, ping
#
# Autenticación: POST /api/auth/token (email + password en PostgreSQL)
# Fallback legacy: NOC_AGENT_TOKEN estático en agent.env
#
# Uso:
#   ./obserlgcr-noc-agent-linux.sh              → heartbeat + acciones (cron)
#   ./obserlgcr-noc-agent-linux.sh --setup      → configurar credenciales y cron
#   ./obserlgcr-noc-agent-linux.sh --renew      → renovar JWT
#   ./obserlgcr-noc-agent-linux.sh --status     → estado token y agenda
#   ./obserlgcr-noc-agent-linux.sh --uninstall  → quitar agenda y archivos locales
# ==============================================================================

set -euo pipefail

OBSERLGCR_URL="${OBSERLGCR_URL:-http://localhost:8787}"
ENV_FILE="${ENV_FILE:-/etc/obserlgcr/noc-agent.env}"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true

AGENT_EMAIL="${AGENT_EMAIL:-}"
AGENT_PASS="${AGENT_PASS:-}"
NOC_AGENT_TOKEN="${NOC_AGENT_TOKEN:-}"
TOKEN_EXPIRES="${TOKEN_EXPIRES:-24h}"
TOKEN_FILE="${TOKEN_FILE:-/etc/obserlgcr/agent.token}"
LOG_FILE="${LOG_FILE:-/var/log/obserlgcr-noc-agent.log}"
NOC_DEVICE_FILE="${NOC_DEVICE_FILE:-/etc/obserlgcr/noc_device_id}"
AGENT_VERSION="2.0.0"
CRON_SCHEDULE="*/5 * * * *"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-5242880}"
JITTER_MAX="${JITTER_MAX:-120}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log() {
  if [[ -f "$LOG_FILE" ]]; then
    local sz; sz=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    [[ "$sz" -gt "$MAX_LOG_BYTES" ]] && mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
  fi
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}
info() { echo -e "${CYAN}→${RESET} $*" >&2; }
ok()   { echo -e "${GREEN}✓${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}⚠${RESET} $*" >&2; }
err()  { echo -e "${RED}✗${RESET} $*" >&2; }

check_deps() {
  local missing=()
  for cmd in curl jq; do command -v "$cmd" &>/dev/null || missing+=("$cmd"); done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Dependencias faltantes: ${missing[*]}"
    exit 1
  fi
}

prepare_log() {
  local dir; dir="$(dirname "$LOG_FILE")"
  if sudo mkdir -p "$dir" 2>/dev/null && sudo touch "$LOG_FILE" 2>/dev/null; then
    sudo chmod 640 "$LOG_FILE" 2>/dev/null || true
  else
    LOG_FILE="$HOME/.obserlgcr/noc-agent.log"
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
  fi
}

save_token() {
  local token="$1" dir; dir="$(dirname "$TOKEN_FILE")"
  if sudo mkdir -p "$dir" 2>/dev/null; then
    echo "$token" | sudo tee "$TOKEN_FILE" >/dev/null
    sudo chmod 600 "$TOKEN_FILE"
  else
    TOKEN_FILE="$HOME/.obserlgcr/agent.token"
    mkdir -p "$(dirname "$TOKEN_FILE")"
    echo "$token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
  fi
}

load_token() {
  if   [[ -f "$TOKEN_FILE" ]];                  then cat "$TOKEN_FILE"
  elif [[ -f "$HOME/.obserlgcr/agent.token" ]]; then cat "$HOME/.obserlgcr/agent.token"
  else echo ""; fi
}

token_valid() {
  local token="$1" b64 exp now pad
  [[ -z "$token" ]] && return 1
  [[ "$token" != *.*.* ]] && [[ -n "$NOC_AGENT_TOKEN" && "$token" == "$NOC_AGENT_TOKEN" ]] && return 0
  [[ "$token" != *.*.* ]] && return 1
  b64=$(echo "$token" | cut -d. -f2 | tr '_-' '/+')
  pad=$(( (4 - ${#b64} % 4) % 4 ))
  b64="${b64}$(printf '%0.s=' $(seq 1 $pad) 2>/dev/null)"
  exp=$(echo "$b64" | base64 -d 2>/dev/null | jq -rs '.[0].exp // 0' 2>/dev/null)
  now=$(date +%s)
  [[ -n "$exp" && "$exp" -gt "$((now + 300))" ]]
}

get_token() {
  if [[ -n "$NOC_AGENT_TOKEN" ]]; then
    echo "$NOC_AGENT_TOKEN"
    return 0
  fi
  if [[ -z "$AGENT_EMAIL" || -z "$AGENT_PASS" ]]; then
    err "Defina AGENT_EMAIL y AGENT_PASS en $ENV_FILE"
    return 1
  fi
  local response success token
  response=$(curl -s -X POST "$OBSERLGCR_URL/api/auth/token" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg e "$AGENT_EMAIL" --arg p "$AGENT_PASS" --arg x "$TOKEN_EXPIRES" \
          '{email:$e,password:$p,expires_in:$x}')" \
    --connect-timeout 10 --max-time 30) || {
    err "No se pudo conectar a $OBSERLGCR_URL"
    return 1
  }
  success=$(echo "$response" | jq -r '.success' 2>/dev/null)
  token=$(echo "$response" | jq -r '.token' 2>/dev/null)
  if [[ "$success" != "true" || -z "$token" || "$token" == "null" ]]; then
    err "Error de autenticación: $(echo "$response" | jq -r '.error // "respuesta inválida"')"
    return 1
  fi
  echo "$token"
}

auth_header() {
  local token="$1"
  echo "Authorization: Bearer $token"
}

collect_base() {
  HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
  DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1)
  DEFAULT_IFACE="${DEFAULT_IFACE:-eth0}"
  IP_ADDRESS=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null \
    | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 \
    || hostname -I 2>/dev/null | awk '{print $1}')
  MAC_ADDRESS=$(cat "/sys/class/net/$DEFAULT_IFACE/address" 2>/dev/null \
    || ip link show 2>/dev/null | grep -oP '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1 \
    || echo "")
}

collect_metrics() {
  local cpu_idle1 cpu_total1 cpu_idle2 cpu_total2
  read -r _ u1 n1 s1 i1 w1 _ _ _ _ < /proc/stat
  cpu_total1=$(( u1 + n1 + s1 + i1 + w1 )); cpu_idle1=$i1
  sleep 1
  read -r _ u2 n2 s2 i2 w2 _ _ _ _ < /proc/stat
  cpu_total2=$(( u2 + n2 + s2 + i2 + w2 )); cpu_idle2=$i2
  local dtotal=$(( cpu_total2 - cpu_total1 ))
  local didle=$(( cpu_idle2 - cpu_idle1 ))
  NOC_CPU_PCT=$(awk "BEGIN {printf \"%.2f\", ($dtotal-$didle)*100/$dtotal}" 2>/dev/null || echo "0")

  local mem_total mem_avail
  mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 1)
  mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  NOC_MEM_PCT=$(awk "BEGIN {printf \"%.2f\", (($mem_total-$mem_avail)/$mem_total)*100}" 2>/dev/null || echo "0")

  local gw; gw=$(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -1)
  NOC_RTT_MS=$(ping -c 1 -W 2 "${gw:-8.8.8.8}" 2>/dev/null \
    | grep -oP 'time=\K[\d.]+' | head -1 || echo "")

  local iface="${DEFAULT_IFACE:-eth0}" rx1 tx1 rx2 tx2
  rx1=$(awk -v iface="$iface" '$1==iface":" {print $2}' /proc/net/dev 2>/dev/null || echo 0)
  tx1=$(awk -v iface="$iface" '$1==iface":" {print $10}' /proc/net/dev 2>/dev/null || echo 0)
  sleep 1
  rx2=$(awk -v iface="$iface" '$1==iface":" {print $2}' /proc/net/dev 2>/dev/null || echo 0)
  tx2=$(awk -v iface="$iface" '$1==iface":" {print $10}' /proc/net/dev 2>/dev/null || echo 0)
  NOC_BW_IN=$(( (rx2 - rx1) * 8 ))
  NOC_BW_OUT=$(( (tx2 - tx1) * 8 ))
}

collect_disk() {
  NOC_DISK_JSON="[]"
  NOC_DISK_JSON=$(df -kP 2>/dev/null | awk 'NR>1 && $1 !~ /^\/dev\/loop/ {
    gsub(/%/,"",$5); print $6"|"$1"|"$2"|"$3"|"$5
  }' | while IFS='|' read -r mp dev size used pct; do
    [[ -z "$mp" ]] && continue
    jq -n --arg mp "$mp" --arg dev "$dev" --argjson size "$size" --argjson used "$used" --argjson pct "$pct" \
      '{mountpoint:$mp,device:$dev,total_bytes:($size*1024),used_bytes:($used*1024),usage_pct:$pct}'
  done | jq -s '.' 2>/dev/null || echo "[]")
}

send_heartbeat() {
  local token="$1"
  local device_id=""
  [[ -f "$NOC_DEVICE_FILE" ]] && device_id=$(cat "$NOC_DEVICE_FILE" 2>/dev/null || echo "")

  collect_metrics
  collect_disk

  local metrics_json
  metrics_json=$(jq -n \
    --arg cpu "$NOC_CPU_PCT" --arg mem "$NOC_MEM_PCT" --arg rtt "${NOC_RTT_MS:-}" \
    --arg bwi "$NOC_BW_IN" --arg bwo "$NOC_BW_OUT" \
    '{
       cpu_pct: ($cpu|tonumber), mem_pct: ($mem|tonumber),
       bw_in_bps: ($bwi|tonumber), bw_out_bps: ($bwo|tonumber)
     } + (if $rtt != "" then {rtt_ms: ($rtt|tonumber)} else {} end)')

  local payload
  payload=$(jq -n \
    --arg hostname "$HOSTNAME_VAL" --arg ip "${IP_ADDRESS:-}" --arg mac "${MAC_ADDRESS:-}" \
    --arg agent_v "$AGENT_VERSION" --arg device_id "$device_id" --argjson metrics "$metrics_json" \
    --argjson disk "$NOC_DISK_JSON" \
    --arg log_msg "NOC_HB host=$HOSTNAME_VAL cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}%" \
    '{hostname:$hostname, ip_address:$ip, mac_address:$mac, agent_version:$agent_v, metrics:$metrics, disk:$disk,
      log_lines:[{severity:"info",source:"noc-agent",message:$log_msg}]}
     + (if $device_id != "" then {device_id:$device_id} else {} end)')

  local response http_code body
  response=$(curl -s -w "\n%{http_code}" -X POST "$OBSERLGCR_URL/api/noc/heartbeat" \
    -H "Content-Type: application/json" -H "$(auth_header "$token")" -d "$payload" \
    --connect-timeout 5 --max-time 20) || { warn "NOC: sin conexión"; return 1; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [[ "$http_code" == "200" ]]; then
    local new_id; new_id=$(echo "$body" | jq -r '.device_id // ""')
    if [[ -n "$new_id" && "$new_id" != "$device_id" ]]; then
      { sudo mkdir -p "$(dirname "$NOC_DEVICE_FILE")" 2>/dev/null && \
        echo "$new_id" | sudo tee "$NOC_DEVICE_FILE" >/dev/null; } \
        || echo "$new_id" > "$NOC_DEVICE_FILE"
    fi
    ok "Heartbeat | cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}% rtt=${NOC_RTT_MS:-?}ms"
    log "NOC_HB host=$HOSTNAME_VAL cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}%"
  elif [[ "$http_code" == "401" ]]; then
    warn "Token expirado, renovando..."
    local new_token; new_token=$(get_token) || return 1
    save_token "$new_token"
    send_heartbeat "$new_token"
  else
    err "Heartbeat HTTP $http_code: $body"
    return 1
  fi
}

poll_actions() {
  local token="$1"
  local device_id=""
  [[ -f "$NOC_DEVICE_FILE" ]] && device_id=$(cat "$NOC_DEVICE_FILE" 2>/dev/null || echo "")
  [[ -z "$device_id" ]] && return 0

  local response http_code body
  response=$(curl -s -w "\n%{http_code}" \
    -H "$(auth_header "$token")" \
    "$OBSERLGCR_URL/api/noc/agent/actions?device_id=$device_id&status=pending" \
    --connect-timeout 5 --max-time 10) || return 0
  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')
  [[ "$http_code" != "200" ]] && return 0

  echo "$body" | jq -c '.data[]?' 2>/dev/null | while IFS= read -r action; do
    local action_id action_type payload_json output exit_code=0
    action_id=$(echo "$action" | jq -r '.id')
    action_type=$(echo "$action" | jq -r '.action_type')
    payload_json=$(echo "$action" | jq -c '.payload // {}')

    curl -s -X PATCH "$OBSERLGCR_URL/api/noc/actions/$action_id" \
      -H "Content-Type: application/json" -H "$(auth_header "$token")" \
      -d '{"status":"running"}' >/dev/null 2>&1 || true

    case "$action_type" in
      ping)
        output=$(ping -c 4 -W 2 "$(echo "$payload_json" | jq -r '.target // "8.8.8.8"')" 2>&1) || exit_code=$?
        ;;
      traceroute)
        output=$(traceroute -m 20 "$(echo "$payload_json" | jq -r '.target // "8.8.8.8"')" 2>&1) || exit_code=$?
        ;;
      restart_service)
        local svc; svc=$(echo "$payload_json" | jq -r '.service // ""')
        if [[ -z "$svc" ]]; then output="Error: service requerido"; exit_code=1
        else output=$(sudo systemctl restart "$svc" 2>&1) || exit_code=$?; fi
        ;;
      reboot)
        curl -s -X PATCH "$OBSERLGCR_URL/api/noc/actions/$action_id" \
          -H "Content-Type: application/json" -H "$(auth_header "$token")" \
          -d '{"status":"done","output":"Reinicio iniciado"}' >/dev/null 2>&1 || true
        log "ACTION reboot"
        sudo reboot
        return 0
        ;;
      *) output="Acción desconocida: $action_type"; exit_code=1 ;;
    esac

    local final_status="done"; [[ $exit_code -ne 0 ]] && final_status="failed"
    local out_json; out_json=$(jq -Rs . <<< "$output")
    curl -s -X PATCH "$OBSERLGCR_URL/api/noc/actions/$action_id" \
      -H "Content-Type: application/json" -H "$(auth_header "$token")" \
      -d "{\"status\":\"$final_status\",\"output\":$out_json}" >/dev/null 2>&1 || true
    log "ACTION $action_type → $final_status"
  done
}

setup_cron() {
  local script_path; script_path=$(realpath "$0")
  (crontab -l 2>/dev/null | grep -v "obserlgcr-noc-agent") | crontab - 2>/dev/null || true
  (crontab -l 2>/dev/null
   echo "$CRON_SCHEDULE ENV_FILE=$ENV_FILE TOKEN_FILE=$TOKEN_FILE $script_path >> $LOG_FILE 2>&1"
  ) | crontab -
  ok "Cron cada 5 minutos"
}

cmd_run() {
  if [[ ! -t 1 && "$JITTER_MAX" -gt 0 ]]; then
    sleep $(( (RANDOM % JITTER_MAX) + 1 ))
  fi
  local token; token=$(load_token)
  if ! token_valid "$token"; then
    info "Obteniendo token..."
    token=$(get_token) || exit 1
    save_token "$token"
  fi
  collect_base
  send_heartbeat "$token" || true
  poll_actions "$token" || true
}

cmd_setup() {
  echo -e "\n${BOLD}obserLGCR — Agente NOC Linux v${AGENT_VERSION}${RESET}\n"
  read -rp "  URL del servidor [$OBSERLGCR_URL]: " url; [[ -n "$url" ]] && OBSERLGCR_URL="$url"
  echo -n "  Email del agente [noc-agent@obserlgcr.local]: "
  read -r email; AGENT_EMAIL="${email:-noc-agent@obserlgcr.local}"
  echo -n "  Password del agente: "
  read -rs pass; echo; AGENT_PASS="$pass"
  echo -n "  Token estático legacy (vacío = usar JWT): "
  read -r tok; NOC_AGENT_TOKEN="${tok:-}"

  local dir; dir=$(dirname "$ENV_FILE")
  if sudo mkdir -p "$dir" 2>/dev/null; then
    sudo tee "$ENV_FILE" >/dev/null <<EOF
OBSERLGCR_URL=$OBSERLGCR_URL
AGENT_EMAIL=$AGENT_EMAIL
AGENT_PASS=$AGENT_PASS
NOC_AGENT_TOKEN=$NOC_AGENT_TOKEN
TOKEN_EXPIRES=$TOKEN_EXPIRES
EOF
    sudo chmod 600 "$ENV_FILE"
    ok "Config en $ENV_FILE (600)"
  else
    mkdir -p "$dir"
    cat > "$ENV_FILE" <<EOF
OBSERLGCR_URL=$OBSERLGCR_URL
AGENT_EMAIL=$AGENT_EMAIL
AGENT_PASS=$AGENT_PASS
NOC_AGENT_TOKEN=$NOC_AGENT_TOKEN
TOKEN_EXPIRES=$TOKEN_EXPIRES
EOF
    chmod 600 "$ENV_FILE"
  fi

  prepare_log
  info "Autenticando..."
  local token; token=$(get_token) || exit 1
  save_token "$token"
  setup_cron
  collect_base
  send_heartbeat "$token"
  ok "Configuración completada."
}

cmd_status() {
  echo -e "\n${BOLD}Estado agente obserLGCR (Linux)${RESET}"
  info "Servidor : $OBSERLGCR_URL"
  info "Email    : ${AGENT_EMAIL:-<no definido>}"
  local token; token=$(load_token)
  if token_valid "$token"; then ok "Token válido"
  else warn "Sin token válido. Ejecutar: $0 --setup o --renew"; fi
  if crontab -l 2>/dev/null | grep -q obserlgcr-noc-agent; then
    ok "Cron activo"; crontab -l | grep obserlgcr-noc-agent
  else warn "Sin cron. Ejecutar: $0 --setup"; fi
  [[ -f "$NOC_DEVICE_FILE" ]] && info "Device ID: $(cat "$NOC_DEVICE_FILE")"
}

cmd_renew() {
  local t; t=$(get_token) || exit 1
  save_token "$t"
  ok "Token renovado."
}

cmd_uninstall() {
  crontab -l 2>/dev/null | grep -v obserlgcr-noc-agent | crontab - 2>/dev/null || true
  sudo rm -rf /etc/obserlgcr 2>/dev/null || rm -rf "$HOME/.obserlgcr" 2>/dev/null || true
  ok "Agente desinstalado (archivos locales)."
}

check_deps
case "${1:-}" in
  --setup)     cmd_setup ;;
  --renew)     cmd_renew ;;
  --status)    cmd_status ;;
  --uninstall) cmd_uninstall ;;
  --help|-h)
    echo "Uso: $(basename "$0") [--setup|--renew|--status|--uninstall]"
    ;;
  *) cmd_run ;;
esac
