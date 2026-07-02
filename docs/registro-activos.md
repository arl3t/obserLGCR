# Registro de activos

Guía completa para registrar servidores y equipos en obserLGCR: agente NOC, inventario de software, credenciales en Config y vías alternativas (SNMP, nmap, API).

## Resumen de vías de registro

| Vía | Dónde se configura | Endpoint / mecanismo | Qué registra |
|-----|-------------------|----------------------|--------------|
| **Agente NOC** | Config → Registro de activos + script en el host | `POST /api/noc/heartbeat` | Dispositivo, métricas (CPU, RAM, disco, RTT) |
| **Inventario agente** (Linux v2.1+) | Mismo agente | `POST /api/inventory/report` | Software, HW, puertos locales, servicios |
| **SNMP descubrimiento** | Config → SNMP | `POST /api/noc/snmp/discover` | Equipos de red con SNMP |
| **SNMP Telegraf** | Config → Registro de activos (JWT) + Telegraf | `POST /api/noc/snmp/ingest` | Métricas + software SNMP |
| **nmap descubrimiento** | `.env` + host runner | IPAM `/discovery` | Hosts, puertos, OS guess |
| **Manual API** | — | `POST /api/noc/devices` o `POST /api/assets` | Alta puntual |

Vista unificada en el dashboard: **Detección → Activos**. Detalle NOC: **NOC → dispositivo**.

---

## Credenciales (Config → `/admin/settings`)

Solo usuarios **admin** ven las secciones de registro.

### Registro de activos — credenciales de agente

| Acción | Descripción |
|--------|-------------|
| Editar email / contraseña | Actualiza `agent_credentials` en PostgreSQL |
| Crear agente | Nuevo email + password para scripts |
| Habilitar / deshabilitar | Toggle por agente |
| URL del API | Para scripts en hosts remotos |
| Snippets | Comandos copiables (JWT, instalación agente) |

**API:** `GET/POST/PATCH /api/agents` (rol admin). Ver [api.md](api.md#credenciales-de-agentes--apiagents).

### Credenciales por defecto (laboratorio)

| Uso | Email | Password |
|-----|-------|----------|
| **Dashboard** (login web) | `admin@obserlgcr.local` | `changeme-admin` |
| **Agente NOC** (scripts) | `noc-agent@obserlgcr.local` | `changeme-noc-agent` |

Son cuentas **distintas**. El login del dashboard no sirve para el agente.

### Tras cambiar la contraseña del agente

En cada host con agente instalado:

```bash
sudo ./obserlgcr-noc-agent-linux.sh --renew
# o repetir --setup con la nueva clave
```

---

## Agente NOC en servidores remotos

### Prerrequisitos en el host monitoreado

| Paquete | Ubuntu/Debian |
|---------|-----------------|
| `curl`, `jq`, `ping` | `sudo apt update && sudo apt install -y curl jq iputils-ping` |

RHEL/Rocky: `sudo dnf install -y curl jq iputils`  
Alpine: `apk add curl jq iputils`

### Instalación

1. Configurar credencial en **Config → Registro de activos** (o `seed-noc-agent.mjs`).
2. En el host a monitorear:

```bash
curl -O http://TU_SERVIDOR:8080/agents/obserlgcr-noc-agent-linux.sh
chmod +x obserlgcr-noc-agent-linux.sh
sudo ./obserlgcr-noc-agent-linux.sh --setup
```

### Valores en `--setup`

| Campo | Valor |
|-------|--------|
| **URL del servidor** | `http://IP_O_DOMINIO:8787` — **incluir `http://`** |
| **Email** | El de Config (p. ej. `noc-agent@obserlgcr.local`) |
| **Password** | El configurado en Config |
| **Token legacy** | Dejar vacío (usa JWT) |

| Dónde corre el agente | `OBSERLGCR_URL` |
|------------------------|-----------------|
| Misma máquina que Docker | `http://localhost:8787` |
| Otro servidor / VPS | `http://IP:8787` |
| nginx proxea `/api` en :8080 | `http://IP:8080` |

> El puerto **5433/5432** de Postgres es interno; el agente **no** lo usa.

### Verificar conectividad

```bash
curl -s http://TU_IP:8787/api/health
# → {"ok":true,"service":"obserlgcr-api",...}
sudo ufw allow 8787/tcp   # si aplica firewall
```

### Archivos locales (Linux)

| Archivo | Contenido |
|---------|-----------|
| `/etc/obserlgcr/noc-agent.env` | URL, email, password |
| `/etc/obserlgcr/agent.token` | JWT renovable |
| `/etc/obserlgcr/noc_device_id` | UUID del dispositivo NOC |
| `/var/log/obserlgcr-noc-agent.log` | Log del agente |

Cron: cada **5 minutos** (heartbeat + acciones).

### Comandos del agente

| Comando | Descripción |
|---------|-------------|
| `--setup` | Configurar credenciales y cron |
| `--inventory` | Forzar reporte de inventario (Linux v2.1+) |
| `--renew` | Renovar JWT |
| `--status` | Token, cron, device ID, último inventario |
| `--uninstall` | Quitar cron y archivos locales |

Documentación ampliada del módulo: [modulo-noc.md](modulo-noc.md).

---

## Inventario de software (agente Linux v2.1+)

El **heartbeat** registra el activo. El **inventario de paquetes** es un reporte aparte.

| Endpoint | Frecuencia default |
|----------|-------------------|
| `POST /api/noc/heartbeat` | Cada 5 min |
| `POST /api/inventory/report` | Cada 6 h (+ al `--setup` / `--inventory`) |

### Qué recoge el inventario

| Dato | Fuente |
|------|--------|
| Identidad (hostname, IP, MAC, OS) | `/etc/os-release`, `machine-id` |
| CPU, RAM | `/proc/cpuinfo`, `/proc/meminfo` |
| Software | `dpkg-query` o `rpm -qa` |
| Particiones | `df -PkT` |
| Puertos en escucha | `ss -H -lntu` |
| Servicios | `systemctl` |

### Variables en `noc-agent.env`

```env
INVENTORY_ENABLED=true
INVENTORY_INTERVAL_SECS=21600
INVENTORY_MAX_PACKAGES=5000
```

### Si ves "Sin inventario de software" en NOC

El heartbeat funciona pero falta el reporte de inventario:

```bash
sudo ./obserlgcr-noc-agent-linux.sh --inventory
```

Refrescar **NOC → detalle → Inventario**.

> **IPAM / discovery:** subred, región y puertos externos vienen de **Detección → Descubrimiento** ([descubrimiento-nmap.md](descubrimiento-nmap.md)), no del agente.

---

## SNMP

### Config → SNMP

| Campo | Uso |
|-------|-----|
| Community por defecto | Polling Telegraf |
| Communities descubrimiento | Scan por segmento CIDR |
| Puerto UDP | Default 161 |
| Descubrimiento en segmento | Registra activos en NOC + `snmp_targets` |

El JWT de Telegraf se obtiene con las credenciales de **Registro de activos**:

```bash
curl -s -X POST http://TU_IP:8787/api/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"noc-agent@obserlgcr.local","password":"TU_PASSWORD","expires_in":"24h"}' | jq -r .token
```

Documentación Telegraf: [noc-snmp-telegraf.md](noc-snmp-telegraf.md).

---

## Shipper de detección (logs, no activos NOC)

```bash
curl -O http://TU_SERVIDOR:8080/agents/obserlgcr-detection-shipper.sh
chmod +x obserlgcr-detection-shipper.sh
./obserlgcr-detection-shipper.sh --setup
```

Usa las **mismas credenciales de agente** (`POST /api/detection/ingest`). No registra dispositivos en NOC.

---

## CLI alternativa (sin UI)

```bash
# Crear / rotar agente
docker compose exec api node scripts/seed-noc-agent.mjs noc-agent@obserlgcr.local 'password-seguro' 'Agente NOC'

# Usuarios dashboard
docker compose exec api node scripts/seed-platform-user.mjs admin@obserlgcr.local 'clave' admin Admin
```

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---------|--------|----------|
| `Dependencias faltantes: jq` | Falta jq en el host | `apt install jq curl` |
| Heartbeat falla / 401 | Password incorrecta o agente deshabilitado | Config → Registro de activos; `--renew` |
| URL sin `http://` | Setup inválido | `http://IP:8787` |
| Activo en NOC, sin software | Sin inventario reportado | `--inventory` (agente v2.1+) |
| IPAM / subred vacíos | Sin discovery nmap | [descubrimiento-nmap.md](descubrimiento-nmap.md) |
| Link IPAM↔NOC pendiente | IP no vinculada | Discovery o documentar host en Detección |
