# Descubrimiento nmap

Escaneo de red en **Detección → Descubrimiento** (`/detection` pestaña Descubrimiento). Usa nmap para descubrir hosts, puertos, servicios y CVEs.

## Por qué existe el host runner

Docker aísla la red del contenedor. Desde el contenedor IPAM **no se alcanza** la LAN física del host (`192.168.x.x`, `10.x.x.x` en la interfaz del VPS).

Por eso obserLGCR delega nmap a un proceso en el **host** (fuera de Docker):

```
Dashboard → API → IPAM → HTTP → nmap-host-runner.py (host :8791) → nmap → LAN
```

En la UI, el badge indica el estado:

| Badge | Significado |
|-------|-------------|
| `nmap OK` | nmap disponible (contenedor o runner) |
| `host runner conectado` | IPAM alcanza `NMAP_RUNNER_URL/health` |
| `host runner sin conexión` | Runner no corre o URL/token incorrectos |

---

## Configuración en `.env`

```env
NMAP_RUNNER_URL=http://host.docker.internal:8791
NMAP_RUNNER_TOKEN=change-me-nmap-runner
NMAP_TIMEOUT_SEC=600
NMAP_HOST_TIMEOUT_SEC=5
```

| Variable | Descripción |
|----------|-------------|
| `NMAP_RUNNER_URL` | URL del runner en el host. Vacío = nmap solo dentro del contenedor IPAM |
| `NMAP_RUNNER_TOKEN` | Token compartido runner ↔ IPAM (header `Authorization: Bearer …`) |
| `NMAP_TIMEOUT_SEC` | Timeout máximo del escaneo completo |
| `NMAP_HOST_TIMEOUT_SEC` | Timeout por host individual |

En Linux, Docker Compose añade `host.docker.internal` vía `extra_hosts: host-gateway` en el servicio `ipam`.

---

## Instalación del host runner (VPS / Linux)

### Opción A — Docker Compose (recomendado)

El servicio `nmap-runner` usa `network_mode: host` para escanear la LAN real y arranca con el stack:

```bash
cd ~/obserLGCR
docker compose up -d nmap-runner ipam
```

Verificar:

```bash
curl -s http://127.0.0.1:8791/health
docker compose exec ipam python -c "from app.services.nmap_runner_client import check_nmap_runner_health; print(check_nmap_runner_health())"
```

Debe imprimir `True`. En el dashboard: **Detección → Descubrimiento** → badge *host runner conectado*.

### Opción B — Script en el host (Mac dev o sin Docker)

#### 1. Dependencias en el host

```bash
sudo apt update
sudo apt install -y nmap python3
```

macOS: `brew install nmap`

### 2. Variables (mismo token que `.env`)

```bash
cd ~/obserLGCR
export NMAP_RUNNER_TOKEN="$(grep ^NMAP_RUNNER_TOKEN= .env | cut -d= -f2-)"
export NMAP_RUNNER_PORT=8791
export NMAP_RUNNER_BIND=0.0.0.0
```

### 3. Arrancar el runner

```bash
./scripts/start-nmap-runner.sh
# o: python3 scripts/nmap-host-runner.py
```

Salida esperada:

```text
nmap host runner en http://0.0.0.0:8791 (health: /health, scan: POST /scan)
```

**Debe quedar corriendo** mientras usás Descubrimiento. Si cerrás la terminal, el badge vuelve a *sin conexión*.

### 4. Verificar

Desde el host:

```bash
curl -s http://127.0.0.1:8791/health
```

Desde el contenedor IPAM:

```bash
cd ~/obserLGCR
TOKEN=$(grep ^NMAP_RUNNER_TOKEN= .env | cut -d= -f2-)
docker compose exec ipam curl -s -H "Authorization: Bearer $TOKEN" \
  http://host.docker.internal:8791/health
```

Respuesta esperada:

```json
{"ok":true,"service":"nmap-host-runner","nmap":true,"bind":"0.0.0.0","port":8791}
```

### 5. Escanear en el dashboard

**Detección → Descubrimiento** → badge *host runner conectado* → **Escanear ahora**.

---

## Servicio systemd (producción)

Reemplazá `/root/obserLGCR` por la ruta real del proyecto:

```bash
sudo tee /etc/systemd/system/obserlgcr-nmap-runner.service <<'EOF'
[Unit]
Description=obserLGCR nmap host runner
After=network.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/obserLGCR
EnvironmentFile=/root/obserLGCR/.env
Environment=NMAP_RUNNER_PORT=8791
Environment=NMAP_RUNNER_BIND=0.0.0.0
ExecStart=/usr/bin/python3 /root/obserLGCR/scripts/nmap-host-runner.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now obserlgcr-nmap-runner
sudo systemctl status obserlgcr-nmap-runner
```

Logs: `journalctl -u obserlgcr-nmap-runner -f`

---

## Perfiles de escaneo

| Perfil | nmap (resumen) |
|--------|----------------|
| `discovery` | `-sn -R` — hosts vivos |
| `quick` | `-T4 -F` — 100 puertos top |
| `standard` | `-T4 -sV -sC` — servicios + scripts |
| `full` | `-T4 -sV -sC -p-` — todos los puertos |
| `stealth` | `-T2 -sS -F` |
| `vulnerabilities` | `--script vuln` — CVE |

Los escaneos largos (/24 completo con `full`) pueden tardar varios minutos. Usá `/28` para pruebas.

---

## Modo sin host runner

Si solo escaneás **IPs públicas** desde el VPS (sin LAN local), podés desactivar el runner:

```env
# .env
NMAP_RUNNER_URL=
```

```bash
docker compose up -d ipam
```

nmap corre **dentro** del contenedor IPAM. No sirve para redes privadas detrás del host.

---

## API del runner

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/health` | Estado (requiere token si configurado) |
| `POST` | `/scan` | Ejecutar nmap; body JSON con `cidr`, `targets`, `profile`, etc. |

Headers: `Authorization: Bearer <NMAP_RUNNER_TOKEN>` o `X-Nmap-Runner-Token`.

Script: [`scripts/nmap-host-runner.py`](../scripts/nmap-host-runner.py).

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---------|--------|----------|
| `host runner sin conexión` | Runner no corre o token distinto | `docker compose up -d nmap-runner` · mismo `NMAP_RUNNER_TOKEN` en `.env` |
| Health 401 | Token distinto | Mismo `NMAP_RUNNER_TOKEN` en `.env` y al exportar |
| `nmap: false` en health | nmap no instalado en host | `apt install nmap` |
| Scan 0 hosts en LAN | Runner no corre o CIDR incorrecto | Verificar runner + segmento alcanzable desde el VPS |
| Timeout | Red grande / perfil `full` | Segmento más pequeño o subir `NMAP_TIMEOUT_SEC` |
| Contenedor no alcanza host | Sin `host.docker.internal` | `docker compose` con `extra_hosts` en ipam (ya incluido) |

### Reiniciar stack tras cambiar `.env`

```bash
docker compose up -d ipam
```

---

## Relación con registro de activos

Los hosts descubiertos aparecen en **Detección → Descubrimiento** y pueden documentarse/vincularse con NOC. Para registro continuo de servidores monitoreados, usá el **agente NOC**: [registro-activos.md](registro-activos.md).
