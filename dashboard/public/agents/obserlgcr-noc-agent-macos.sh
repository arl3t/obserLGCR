#!/bin/bash
# ==============================================================================
# obserLGCR — Agente NOC para macOS (Apple Silicon M-series / Intel)
# Plataforma: macOS 12+ (probado en Apple Silicon M4, arm64)
# Requiere: curl, jq, ping (incluidos en macOS)
#
# Autenticación: POST /api/auth/token (email + password en PostgreSQL)
# Fallback legacy: NOC_AGENT_TOKEN estático en agent.env
#
# Uso:
#   ./obserlgcr-noc-agent-macos.sh              → heartbeat + acciones (launchd/cron)
#   ./obserlgcr-noc-agent-macos.sh --setup      → configurar credenciales y launchd
#   ./obserlgcr-noc-agent-macos.sh --renew      → renovar JWT
#   ./obserlgcr-noc-agent-macos.sh --status     → estado token y agenda
#   ./obserlgcr-noc-agent-macos.sh --uninstall  → quitar launchd y archivos locales
# ==============================================================================

set -euo pipefail

OBSERLGCR_URL="${OBSERLGCR_URL:-http://localhost:8787}"
ENV_FILE="${ENV_FILE:-/etc/obserlgcr/noc-agent.env}"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true
[[ -f "$HOME/.obserlgcr/noc-agent.env" ]] && source "$HOME/.obserlgcr/noc-agent.env" || true

AGENT_EMAIL="${AGENT_EMAIL:-}"
AGENT_PASS="${AGENT_PASS:-}"
NOC_AGENT_TOKEN="${NOC_AGENT_TOKEN:-}"
TOKEN_EXPIRES="${TOKEN_EXPIRES:-24h}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.obserlgcr/agent.token}"
LOG_FILE="${LOG_FILE:-$HOME/Library/Logs/obserlgcr-noc-agent.log}"
NOC_DEVICE_FILE="${NOC_DEVICE_FILE:-$HOME/.obserlgcr/noc_device_id}"
AGENT_VERSION="2.0.0-macos"
LAUNCHD_LABEL="com.obserlgcr.noc-agent"
JITTER_MAX="${JITTER_MAX:-120}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-5242880}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log() {
  mkdir -p "$(dirname "$LOG_FILE")"
  if [[ -f "$LOG_FILE" ]]; then
    local sz; sz=$(stat -f %z "$LOG_FILE" 2>/dev/null || echo 0)
    [[ "$sz" -gt "$MAX_LOG_BYTES" ]] && mv "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
  fi
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}
info() { echo -e "${CYAN}→${RESET} $*" >&2; }
ok()   { echo -e "${GREEN}✓${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}⚠${RESET} $*" >&2; }
err()  { echo -e "${RED}✗${RESET} $*" >&2; }

check_deps() {
  local missing=()
  for cmd in curl jq; do command -v "$cmd" &>/dev/null || missing+=("$cmd"); done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Instalar dependencias: brew install ${missing[*]}"
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p "$(dirname "$ENV_FILE")" "$(dirname "$TOKEN_FILE")" "$(dirname "$NOC_DEVICE_FILE")" "$(dirname "$LOG_FILE")"
}

save_token() {
  ensure_dirs
  echo "$1" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
}

load_token() {
  [[ -f "$TOKEN_FILE" ]] && cat "$TOKEN_FILE" || echo ""
}

token_valid() {
  local token="$1" b64 exp now pad
  [[ -z "$token" ]] && return 1
  [[ "$token" != *.*.* ]] && [[ -n "$NOC_AGENT_TOKEN" && "$token" == "$NOC_AGENT_TOKEN" ]] && return 0
  [[ "$token" != *.*.* ]] && return 1
  b64=$(echo "$token" | cut -d. -f2 | tr '_-' '/+')
  pad=$(( (4 - ${#b64} % 4) % 4 ))
  b64="${b64}$(printf '%0.s=' $(seq 1 $pad) 2>/dev/null)"
  exp=$(echo "$b64" | base64 -D 2>/dev/null | jq -rs '.[0].exp // 0' 2>/dev/null)
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
  echo "Authorization: Bearer $1"
}

collect_base() {
  HOSTNAME_VAL=$(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || hostname)
  DEFAULT_IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' | head -1)
  DEFAULT_IFACE="${DEFAULT_IFACE:-en0}"
  IP_ADDRESS=$(ipconfig getifaddr "$DEFAULT_IFACE" 2>/dev/null \
    || ipconfig getifaddr en0 2>/dev/null \
    || echo "")
  MAC_ADDRESS=$(ifconfig "$DEFAULT_IFACE" 2>/dev/null | awk '/ether/{print $2; exit}')
  OS_ARCH=$(uname -m)
}

collect_metrics() {
  # CPU: parsear línea idle de top (compatible Apple Silicon M4)
  local cpu_line idle
  cpu_line=$(top -l 1 -n 0 2>/dev/null | awk '/CPU usage/')
  idle=$(echo "$cpu_line" | sed -n 's/.*, \([0-9.]*\)% idle.*/\1/p')
  if [[ -n "$idle" ]]; then
    NOC_CPU_PCT=$(awk "BEGIN {printf \"%.2f\", 100 - $idle}")
  else
    NOC_CPU_PCT=$(ps -A -o %cpu= 2>/dev/null | awk '{s+=$1} END {printf "%.2f", s+0}')
  fi

  # Memoria: vm_stat + hw.pagesize (presión real en macOS)
  local page_size pages_wired pages_active pages_compressed mem_total mem_used
  page_size=$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)
  mem_total=$(sysctl -n hw.memsize 2>/dev/null || echo 1)
  pages_wired=$(vm_stat 2>/dev/null | awk '/Pages wired/ {gsub(/\./,""); print $4}')
  pages_active=$(vm_stat 2>/dev/null | awk '/Pages active/ {gsub(/\./,""); print $3}')
  pages_compressed=$(vm_stat 2>/dev/null | awk '/Pages occupied by compressor/ {gsub(/\./,""); print $5}')
  pages_wired=${pages_wired:-0}; pages_active=${pages_active:-0}; pages_compressed=${pages_compressed:-0}
  mem_used=$(( (pages_wired + pages_active + pages_compressed) * page_size ))
  NOC_MEM_PCT=$(awk "BEGIN {printf \"%.2f\", ($mem_used/$mem_total)*100}")

  local gw; gw=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}' | head -1)
  NOC_RTT_MS=$(ping -c 1 -W 2000 "${gw:-8.8.8.8}" 2>/dev/null \
    | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p' | head -1 || echo "")

  # Ancho de banda: netstat -I (bytes en interfaz activa)
  local iface="${DEFAULT_IFACE:-en0}" rx1 tx1 rx2 tx2
  rx1=$(netstat -I "$iface" -b 2>/dev/null | awk 'NR==2 {print $7}')
  tx1=$(netstat -I "$iface" -b 2>/dev/null | awk 'NR==2 {print $10}')
  rx1=${rx1:-0}; tx1=${tx1:-0}
  sleep 1
  rx2=$(netstat -I "$iface" -b 2>/dev/null | awk 'NR==2 {print $7}')
  tx2=$(netstat -I "$iface" -b 2>/dev/null | awk 'NR==2 {print $10}')
  rx2=${rx2:-0}; tx2=${tx2:-0}
  NOC_BW_IN=$(( (rx2 - rx1) * 8 ))
  NOC_BW_OUT=$(( (tx2 - tx1) * 8 ))
}

collect_disk() {
  NOC_DISK_JSON="[]"
  if command -v df &>/dev/null; then
    NOC_DISK_JSON=$(df -kP 2>/dev/null | awk 'NR>1 && $1 !~ /^\/dev\/loop/ {
      gsub(/%/,"",$5); print $6"|"$1"|"$2"|"$3"|"$5
    }' | while IFS='|' read -r mp dev size used pct; do
      [[ -z "$mp" ]] && continue
      jq -n --arg mp "$mp" --arg dev "$dev" --argjson size "$size" --argjson used "$used" --argjson pct "$pct" \
        '{mountpoint:$mp,device:$dev,total_bytes:($size*1024),used_bytes:($used*1024),usage_pct:$pct}'
    done | jq -s '.')
  fi
  [[ -z "$NOC_DISK_JSON" || "$NOC_DISK_JSON" == "null" ]] && NOC_DISK_JSON="[]"
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
    --arg log_msg "NOC_HB host=$HOSTNAME_VAL arch=$OS_ARCH cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}%" \
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
      echo "$new_id" > "$NOC_DEVICE_FILE"
      chmod 600 "$NOC_DEVICE_FILE"
    fi
    ok "Heartbeat | arch=$OS_ARCH cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}% rtt=${NOC_RTT_MS:-?}ms"
    log "NOC_HB host=$HOSTNAME_VAL arch=$OS_ARCH cpu=${NOC_CPU_PCT}% mem=${NOC_MEM_PCT}%"
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
        output=$(ping -c 4 "$(echo "$payload_json" | jq -r '.target // "8.8.8.8"')" 2>&1) || exit_code=$?
        ;;
      traceroute)
        output=$(traceroute -m 20 "$(echo "$payload_json" | jq -r '.target // "8.8.8.8"')" 2>&1) || exit_code=$?
        ;;
      restart_service)
        local svc label
        svc=$(echo "$payload_json" | jq -r '.service // ""')
        label=$(echo "$payload_json" | jq -r '.label // ""')
        if [[ -z "$svc" && -z "$label" ]]; then
          output="Error: service o label requerido (launchd)"; exit_code=1
        elif [[ -n "$label" ]]; then
          output=$(launchctl kickstart -k "gui/$(id -u)/$label" 2>&1) || exit_code=$?
        else
          output=$(sudo launchctl kickstart -k "system/$svc" 2>&1) || exit_code=$?
        fi
        ;;
      reboot)
        curl -s -X PATCH "$OBSERLGCR_URL/api/noc/actions/$action_id" \
          -H "Content-Type: application/json" -H "$(auth_header "$token")" \
          -d '{"status":"done","output":"Reinicio iniciado"}' >/dev/null 2>&1 || true
        log "ACTION reboot"
        sudo shutdown -r now "Reinicio solicitado por obserLGCR NOC"
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

install_launchd() {
  local script_path plist_dir plist_path
  script_path=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  plist_dir="$HOME/Library/LaunchAgents"
  plist_path="$plist_dir/${LAUNCHD_LABEL}.plist"
  mkdir -p "$plist_dir"

  cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${script_path}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>ENV_FILE</key>
    <string>${ENV_FILE}</string>
    <key>TOKEN_FILE</key>
    <string>${TOKEN_FILE}</string>
  </dict>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_FILE}</string>
  <key>StandardErrorPath</key>
  <string>${LOG_FILE}</string>
</dict>
</plist>
EOF

  launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$plist_path"
  launchctl enable "gui/$(id -u)/${LAUNCHD_LABEL}"
  ok "launchd instalado (cada 5 min): $plist_path"
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
  echo -e "\n${BOLD}obserLGCR — Agente NOC macOS v${AGENT_VERSION}${RESET}"
  echo -e "  Arquitectura detectada: $(uname -m) ($(sw_vers -productVersion 2>/dev/null || echo macOS))\n"

  read -rp "  URL del servidor [$OBSERLGCR_URL]: " url; [[ -n "$url" ]] && OBSERLGCR_URL="$url"
  echo -n "  Email del agente [noc-agent@obserlgcr.local]: "
  read -r email; AGENT_EMAIL="${email:-noc-agent@obserlgcr.local}"
  echo -n "  Password del agente [changeme-noc-agent]: "
  read -rs pass; echo
  AGENT_PASS="${pass:-changeme-noc-agent}"
  echo -n "  Token estático legacy (vacío = JWT): "
  read -r tok; NOC_AGENT_TOKEN="${tok:-}"

  # macOS sin root: config en $HOME/.obserlgcr
  if [[ ! -w /etc ]] || [[ "$EUID" -ne 0 ]]; then
    ENV_FILE="$HOME/.obserlgcr/noc-agent.env"
    TOKEN_FILE="$HOME/.obserlgcr/agent.token"
    NOC_DEVICE_FILE="$HOME/.obserlgcr/noc_device_id"
    warn "Usando config en $HOME/.obserlgcr (sin sudo)"
  fi

  ensure_dirs
  cat > "$ENV_FILE" <<EOF
OBSERLGCR_URL=$OBSERLGCR_URL
AGENT_EMAIL=$AGENT_EMAIL
AGENT_PASS=$AGENT_PASS
NOC_AGENT_TOKEN=$NOC_AGENT_TOKEN
TOKEN_EXPIRES=$TOKEN_EXPIRES
EOF
  chmod 600 "$ENV_FILE"
  ok "Config en $ENV_FILE (600)"

  info "Autenticando contra PostgreSQL vía API..."
  local token; token=$(get_token) || exit 1
  save_token "$token"
  install_launchd
  collect_base
  send_heartbeat "$token"
  ok "Configuración completada."
}

cmd_status() {
  echo -e "\n${BOLD}Estado agente obserLGCR (macOS)${RESET}"
  info "Servidor : $OBSERLGCR_URL"
  info "Arch     : $(uname -m)"
  info "Email    : ${AGENT_EMAIL:-<no definido>}"
  local token; token=$(load_token)
  if token_valid "$token"; then ok "Token válido"
  else warn "Sin token válido. Ejecutar: $0 --renew"; fi
  if launchctl print "gui/$(id -u)/${LAUNCHD_LABEL}" &>/dev/null; then
    ok "launchd activo: ${LAUNCHD_LABEL}"
  else
    warn "launchd no cargado. Ejecutar: $0 --setup"
  fi
  [[ -f "$NOC_DEVICE_FILE" ]] && info "Device ID: $(cat "$NOC_DEVICE_FILE")"
}

cmd_renew() {
  local t; t=$(get_token) || exit 1
  save_token "$t"
  ok "Token renovado."
}

cmd_uninstall() {
  launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
  rm -rf "$HOME/.obserlgcr" /etc/obserlgcr 2>/dev/null || true
  ok "Agente desinstalado."
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
