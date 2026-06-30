#!/bin/bash
# ==============================================================================
# obserLGCR — Shipper de logs para Detección
# Envía eventos etiquetados por source_log a POST /api/detection/ingest
#
# Tipos admitidos (source_log): ver GET /api/detection/log-types
# Ejemplos: wazuh_alerts, suricata, fortigate, opnsense_filterlog, pmg_phishing, syslog
#
# Uso:
#   ./obserlgcr-detection-shipper.sh --setup
#   ./obserlgcr-detection-shipper.sh --send suricata /path/to/eve.json
#   ./obserlgcr-detection-shipper.sh --tail wazuh_alerts /var/ossec/logs/alerts/alerts.json
#   ./obserlgcr-detection-shipper.sh --run-once          # todas las fuentes en shipper.conf
#   ./obserlgcr-detection-shipper.sh --list-types
# ==============================================================================

set -euo pipefail

OBSERLGCR_URL="${OBSERLGCR_URL:-http://localhost:8787}"
ENV_FILE="${ENV_FILE:-$HOME/.obserlgcr/detection-shipper.env}"
CONF_FILE="${CONF_FILE:-$HOME/.obserlgcr/detection-shipper.conf}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.obserlgcr/agent.token}"
AGENT_EMAIL="${AGENT_EMAIL:-}"
AGENT_PASS="${AGENT_PASS:-}"
NOC_AGENT_TOKEN="${NOC_AGENT_TOKEN:-}"
BATCH_SIZE="${BATCH_SIZE:-50}"
AGENT_ID="${AGENT_ID:-$(hostname -s 2>/dev/null || echo shipper)}"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
info() { echo -e "${CYAN}→${RESET} $*" >&2; }
ok()   { echo -e "${GREEN}✓${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}⚠${RESET} $*" >&2; }
err()  { echo -e "${RED}✗${RESET} $*" >&2; }

[[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true

check_deps() {
  for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || { err "Requiere: $cmd"; exit 1; }
  done
}

load_token() {
  [[ -f "$TOKEN_FILE" ]] && cat "$TOKEN_FILE" || echo ""
}

get_token() {
  if [[ -n "$NOC_AGENT_TOKEN" ]]; then
    echo "$NOC_AGENT_TOKEN"
    return
  fi
  local t; t=$(load_token)
  [[ -n "$t" ]] && { echo "$t"; return; }
  if [[ -z "$AGENT_EMAIL" || -z "$AGENT_PASS" ]]; then
    err "Defina credenciales en $ENV_FILE o ejecute --setup"
    exit 1
  fi
  local response success token
  response=$(curl -s -X POST "$OBSERLGCR_URL/api/auth/token" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg e "$AGENT_EMAIL" --arg p "$AGENT_PASS" '{email:$e,password:$p,expires_in:"24h"}')")
  success=$(echo "$response" | jq -r '.success')
  token=$(echo "$response" | jq -r '.token')
  if [[ "$success" != "true" || -z "$token" || "$token" == "null" ]]; then
    err "Auth fallida: $(echo "$response" | jq -r '.error // .')"
    exit 1
  fi
  mkdir -p "$(dirname "$TOKEN_FILE")"
  echo "$token" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  echo "$token"
}

# Parsea línea según formato → evento JSON para API
parse_line() {
  local source_log="$1" format="$2" line="$3" host="${4:-$(hostname -f 2>/dev/null || hostname)}"
  case "$format" in
    json|jsonl)
      if echo "$line" | jq -e . >/dev/null 2>&1; then
        local sev msg rule src
        sev=$(echo "$line" | jq -r '.severity // .level // .alert.severity // .rule.level // "info"' 2>/dev/null | tr '[:upper:]' '[:lower:]')
        msg=$(echo "$line" | jq -r '.message // .full_log // .alert.description // .rule.description // .signature // .action // .' 2>/dev/null | head -c 4000)
        rule=$(echo "$line" | jq -r '.rule.id // .alert.signature_id // .sid // empty' 2>/dev/null)
        src=$(echo "$line" | jq -r '.src_ip // .alert.data.srcip // .srcip // empty' 2>/dev/null)
        jq -n \
          --arg sl "$source_log" --arg sev "$sev" --arg msg "$msg" --arg host "$host" \
          --arg rule "${rule:-}" --arg src "${src:-}" --argjson raw "$line" \
          '{
            source_log: $sl,
            severity: (if ($sev|test("crit|12|13|14|15")) then "critical"
                       elif ($sev|test("err|high|10|11")) then "error"
                       elif ($sev|test("warn|medium|7|8|9")) then "warn"
                       else "info" end),
            hostname: $host,
            message: ($msg|tostring),
            rule_id: (if $rule != "" then $rule else null end),
            src_ip: (if $src != "" then $src else null end),
            raw: ($raw|fromjson? // $raw)
          }'
      else
        jq -n --arg sl "$source_log" --arg msg "$line" --arg host "$host" \
          '{source_log:$sl, severity:"info", hostname:$host, message:$msg}'
      fi
      ;;
    syslog|line|*)
      local sev="info"
      echo "$line" | grep -qiE 'crit|alert|emerg' && sev="critical"
      echo "$line" | grep -qiE 'error|err' && sev="error"
      echo "$line" | grep -qiE 'warn|warning' && sev="warn"
      jq -n --arg sl "$source_log" --arg sev "$sev" --arg msg "$line" --arg host "$host" \
        '{source_log:$sl, severity:$sev, hostname:$host, message:$msg}'
      ;;
  esac
}

send_batch() {
  local token="$1" payload="$2"
  local response http_code body
  response=$(curl -s -w "\n%{http_code}" -X POST "$OBSERLGCR_URL/api/detection/ingest" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    -H "X-Agent-Id: $AGENT_ID" \
    -d "$payload" --connect-timeout 10 --max-time 60) || {
    err "Sin conexión con $OBSERLGCR_URL"
    return 1
  }
  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')
  if [[ "$http_code" == "201" || "$http_code" == "200" ]]; then
    local n; n=$(echo "$body" | jq -r '.inserted // 0')
    ok "Ingestados $n eventos"
    return 0
  fi
  err "HTTP $http_code: $body"
  return 1
}

ship_file() {
  local source_log="$1" file="$2" format="${3:-jsonl}"
  [[ -f "$file" ]] || { warn "No existe: $file"; return 0; }
  local token; token=$(get_token)
  local batch="[]" count=0 total=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line// }" ]] && continue
    local ev; ev=$(parse_line "$source_log" "$format" "$line") || continue
    batch=$(echo "$batch" | jq --argjson e "$ev" '. + [$e]')
    count=$((count + 1))
    if [[ $count -ge $BATCH_SIZE ]]; then
      send_batch "$token" "$(jq -n --argjson events "$batch" '{events:$events}')" || true
      total=$((total + count))
      batch="[]"
      count=0
    fi
  done < "$file"
  if [[ $count -gt 0 ]]; then
    send_batch "$token" "$(jq -n --argjson events "$batch" '{events:$events}')" || true
    total=$((total + count))
  fi
  info "$source_log: $total líneas procesadas desde $file"
}

tail_file() {
  local source_log="$1" file="$2" format="${3:-jsonl}"
  [[ -f "$file" ]] || { err "Archivo no encontrado: $file"; exit 1; }
  info "Tail $source_log ← $file (Ctrl+C para salir)"
  tail -n 0 -F "$file" 2>/dev/null | while IFS= read -r line; do
    [[ -z "${line// }" ]] && continue
    local token ev payload
    token=$(get_token)
    ev=$(parse_line "$source_log" "$format" "$line") || continue
    payload=$(jq -n --argjson events "[$ev]" '{events:$events}')
    send_batch "$token" "$payload" || true
  done
}

cmd_setup() {
  echo ""
  echo "obserLGCR — Detection log shipper"
  read -rp "  URL API [$OBSERLGCR_URL]: " url; [[ -n "$url" ]] && OBSERLGCR_URL="$url"
  echo -n "  Email agente [noc-agent@obserlgcr.local]: "
  read -r email; AGENT_EMAIL="${email:-noc-agent@obserlgcr.local}"
  echo -n "  Password agente: "
  read -rs pass; echo; AGENT_PASS="$pass"

  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<EOF
OBSERLGCR_URL=$OBSERLGCR_URL
AGENT_EMAIL=$AGENT_EMAIL
AGENT_PASS=$AGENT_PASS
AGENT_ID=$AGENT_ID
BATCH_SIZE=$BATCH_SIZE
EOF
  chmod 600 "$ENV_FILE"

  if [[ ! -f "$CONF_FILE" ]]; then
    cat > "$CONF_FILE" <<'EOF'
# source_log|archivo|formato (jsonl, json, syslog, line)
# Descomente y ajuste rutas locales:
# suricata|/var/log/suricata/eve.json|jsonl
# wazuh_alerts|/var/ossec/logs/alerts/alerts.json|jsonl
# fortigate|/var/log/fortigate.log|syslog
# opnsense_filterlog|/var/log/filter.log|syslog
# pmg_phishing|/var/log/pmg.log|syslog
# syslog|/var/log/syslog|syslog
EOF
    chmod 600 "$CONF_FILE"
  fi

  get_token >/dev/null
  ok "Config: $ENV_FILE"
  ok "Fuentes: $CONF_FILE"
  ok "Listo. Ejecute --run-once o --tail SOURCE FILE"
}

cmd_run_once() {
  [[ -f "$CONF_FILE" ]] || { err "Sin $CONF_FILE — ejecute --setup"; exit 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line// /}"
    [[ -z "$line" ]] && continue
    IFS='|' read -r sl file fmt <<< "$line"
    ship_file "$sl" "$file" "${fmt:-jsonl}"
  done < "$CONF_FILE"
}

cmd_list_types() {
  local token; token=$(get_token)
  curl -s -H "Authorization: Bearer $token" "$OBSERLGCR_URL/api/detection/log-types" | jq -r \
    '.log_types[]? | "\(.source_log)\t\(.sensor_family)\t\(.source_category)\t\(.enabled)"' | column -t -s $'\t' 2>/dev/null \
    || curl -s "$OBSERLGCR_URL/api/detection/log-types" | jq .
}

check_deps
case "${1:-}" in
  --setup)     cmd_setup ;;
  --send)      [[ $# -ge 3 ]] || { err "Uso: --send SOURCE_LOG FILE [format]"; exit 1; }; ship_file "$2" "$3" "${4:-jsonl}" ;;
  --tail)      [[ $# -ge 3 ]] || { err "Uso: --tail SOURCE_LOG FILE [format]"; exit 1; }; tail_file "$2" "$3" "${4:-jsonl}" ;;
  --run-once)  cmd_run_once ;;
  --list-types) cmd_list_types ;;
  --help|-h)
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    err "Uso: $(basename "$0") [--setup|--send|--tail|--run-once|--list-types]"
    exit 1
    ;;
esac
