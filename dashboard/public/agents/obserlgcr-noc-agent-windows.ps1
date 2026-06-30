# ==============================================================================
# obserLGCR — Agente NOC para Windows
# Plataforma: Windows 10/11, Windows Server 2016+
# Requiere: PowerShell 5.1+ (incluido en Windows), acceso HTTP al API
#
# Autenticación: POST /api/auth/token (email + password en PostgreSQL)
# Fallback legacy: NOC_AGENT_TOKEN estático en noc-agent.env
#
# Uso (PowerShell como administrador recomendado para servicios/reboot):
#   .\obserlgcr-noc-agent-windows.ps1              → heartbeat + acciones
#   .\obserlgcr-noc-agent-windows.ps1 -Setup       → configurar credenciales y tarea programada
#   .\obserlgcr-noc-agent-windows.ps1 -Renew       → renovar JWT
#   .\obserlgcr-noc-agent-windows.ps1 -Status     → estado token y agenda
#   .\obserlgcr-noc-agent-windows.ps1 -Uninstall   → quitar tarea y archivos locales
# ==============================================================================

#Requires -Version 5.1

param(
    [switch]$Setup,
    [switch]$Renew,
    [switch]$Status,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$Script:AGENT_VERSION = "2.0.0-windows"
$Script:TASK_NAME = "obserLGCR-NOC-Agent"
$Script:TOKEN_EXPIRES = "24h"
$Script:JITTER_MAX = 120
$Script:MAX_LOG_BYTES = 5MB

function Get-BaseDir {
    $programData = Join-Path $env:ProgramData "obserLGCR"
    try {
        if (-not (Test-Path $programData)) {
            New-Item -ItemType Directory -Path $programData -Force | Out-Null
        }
        $test = Join-Path $programData ".write-test"
        "ok" | Set-Content -Path $test -Force
        Remove-Item $test -Force
        return $programData
    } catch {
        $fallback = Join-Path $env:USERPROFILE ".obserlgcr"
        if (-not (Test-Path $fallback)) {
            New-Item -ItemType Directory -Path $fallback -Force | Out-Null
        }
        return $fallback
    }
}

$Script:BaseDir = Get-BaseDir
$Script:EnvFile = Join-Path $Script:BaseDir "noc-agent.env"
$Script:TokenFile = Join-Path $Script:BaseDir "agent.token"
$Script:DeviceFile = Join-Path $Script:BaseDir "noc_device_id"
$Script:LogFile = Join-Path $Script:BaseDir "logs\noc-agent.log"

$Script:OBSERLGCR_URL = "http://localhost:8787"
$Script:AGENT_EMAIL = ""
$Script:AGENT_PASS = ""
$Script:NOC_AGENT_TOKEN = ""

function Write-Log([string]$Message) {
    $logDir = Split-Path $Script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    if (Test-Path $Script:LogFile) {
        $size = (Get-Item $Script:LogFile).Length
        if ($size -gt $Script:MAX_LOG_BYTES) {
            Move-Item $Script:LogFile "$Script:LogFile.1" -Force -ErrorAction SilentlyContinue
        }
    }
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
    if ($Host.Name -ne "DefaultHost") { Write-Host $line }
}

function Write-Info([string]$Message) { Write-Host "→ $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "✓ $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "⚠ $Message" -ForegroundColor Yellow }
function Write-Err([string]$Message) { Write-Host "✗ $Message" -ForegroundColor Red }

function Import-AgentEnv {
    if (-not (Test-Path $Script:EnvFile)) { return }
    Get-Content $Script:EnvFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { return }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        switch ($key) {
            "OBSERLGCR_URL" { $Script:OBSERLGCR_URL = $val }
            "AGENT_EMAIL" { $Script:AGENT_EMAIL = $val }
            "AGENT_PASS" { $Script:AGENT_PASS = $val }
            "NOC_AGENT_TOKEN" { $Script:NOC_AGENT_TOKEN = $val }
            "TOKEN_EXPIRES" { $Script:TOKEN_EXPIRES = $val }
        }
    }
}

function Save-AgentEnv {
    $content = @(
        "OBSERLGCR_URL=$($Script:OBSERLGCR_URL)"
        "AGENT_EMAIL=$($Script:AGENT_EMAIL)"
        "AGENT_PASS=$($Script:AGENT_PASS)"
        "NOC_AGENT_TOKEN=$($Script:NOC_AGENT_TOKEN)"
        "TOKEN_EXPIRES=$($Script:TOKEN_EXPIRES)"
    ) -join "`n"
    Set-Content -Path $Script:EnvFile -Value $content -Encoding UTF8 -Force
    try {
        icacls $Script:EnvFile /inheritance:r /grant:r "$($env:USERNAME):(R)" "SYSTEM:(F)" "Administrators:(F)" | Out-Null
    } catch { }
}

function Load-Token {
    if (Test-Path $Script:TokenFile) {
        return (Get-Content $Script:TokenFile -Raw -Encoding UTF8).Trim()
    }
    return ""
}

function Save-Token([string]$Token) {
    Set-Content -Path $Script:TokenFile -Value $Token -Encoding UTF8 -NoNewline -Force
    try {
        icacls $Script:TokenFile /inheritance:r /grant:r "$($env:USERNAME):(R)" "SYSTEM:(F)" "Administrators:(F)" | Out-Null
    } catch { }
}

function Decode-JwtPayload([string]$Token) {
    $parts = $Token.Split(".")
    if ($parts.Count -ne 3) { return $null }
    $payload = $parts[1].Replace("-", "+").Replace("_", "/")
    switch ($payload.Length % 4) {
        2 { $payload += "==" }
        3 { $payload += "=" }
    }
    $bytes = [Convert]::FromBase64String($payload)
    $json = [Text.Encoding]::UTF8.GetString($bytes)
    return $json | ConvertFrom-Json
}

function Test-TokenValid([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    if ($Token -notmatch "\..+\.") {
        return (-not [string]::IsNullOrWhiteSpace($Script:NOC_AGENT_TOKEN)) -and ($Token -eq $Script:NOC_AGENT_TOKEN)
    }
    try {
        $payload = Decode-JwtPayload $Token
        if ($null -eq $payload -or $null -eq $payload.exp) { return $false }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        return [int64]$payload.exp -gt ($now + 300)
    } catch {
        return $false
    }
}

function Invoke-Api {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Token,
        [object]$Body = $null
    )
    $uri = "$($Script:OBSERLGCR_URL.TrimEnd('/'))$Path"
    $headers = @{ Authorization = "Bearer $Token" }
    $params = @{
        Method = $Method
        Uri = $uri
        Headers = $headers
        TimeoutSec = 30
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = ($Body | ConvertTo-Json -Depth 6 -Compress)
    }
    try {
        $response = Invoke-WebRequest @params
        return @{ StatusCode = [int]$response.StatusCode; Body = $response.Content }
    } catch {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $text = $reader.ReadToEnd()
            $reader.Close()
            return @{ StatusCode = [int]$_.Exception.Response.StatusCode.value__; Body = $text }
        }
        throw
    }
}

function Get-AgentToken {
    if (-not [string]::IsNullOrWhiteSpace($Script:NOC_AGENT_TOKEN)) {
        return $Script:NOC_AGENT_TOKEN
    }
    if ([string]::IsNullOrWhiteSpace($Script:AGENT_EMAIL) -or [string]::IsNullOrWhiteSpace($Script:AGENT_PASS)) {
        throw "Defina AGENT_EMAIL y AGENT_PASS en $Script:EnvFile"
    }
    $body = @{
        email = $Script:AGENT_EMAIL
        password = $Script:AGENT_PASS
        expires_in = $Script:TOKEN_EXPIRES
    }
    $uri = "$($Script:OBSERLGCR_URL.TrimEnd('/'))/api/auth/token"
    try {
        $response = Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body ($body | ConvertTo-Json) -TimeoutSec 30
    } catch {
        throw "No se pudo conectar a $($Script:OBSERLGCR_URL)"
    }
    if (-not $response.success -or [string]::IsNullOrWhiteSpace($response.token)) {
        $err = if ($response.error) { $response.error } else { "respuesta inválida" }
        throw "Error de autenticación: $err"
    }
    return $response.token
}

function Get-NetworkInfo {
    $hostname = $env:COMPUTERNAME
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($hostname).HostName
        if ($fqdn) { $hostname = $fqdn }
    } catch { }

    $adapter = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
        Select-Object -First 1

    $ip = $null
    $mac = $null
    if ($adapter) {
        $ip = ($adapter.IPv4Address | Select-Object -First 1).IPAddress
        $mac = $adapter.NetAdapter.MacAddress
    }
    if (-not $ip) {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1).IPAddress
    }

    return @{
        Hostname = $hostname
        IpAddress = $ip
        MacAddress = $mac
    }
}

function Get-Metrics {
    $cpu = 0.0
    try {
        $sample1 = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
        Start-Sleep -Seconds 1
        $sample2 = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
        $cpu = [math]::Round(($sample1 + $sample2) / 2, 2)
    } catch {
        $cpu = 0.0
    }

    $memPct = 0.0
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $total = [double]$os.TotalVisibleMemorySize
        $free = [double]$os.FreePhysicalMemory
        if ($total -gt 0) {
            $memPct = [math]::Round((($total - $free) / $total) * 100, 2)
        }
    } catch { }

    $rtt = $null
    try {
        $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction Stop
        if ($ping.ResponseTime) { $rtt = [int]$ping.ResponseTime }
    } catch { }

    $bwIn = 0
    $bwOut = 0
    try {
        $netAdapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        if ($netAdapter) {
            $s1 = Get-NetAdapterStatistics -Name $netAdapter.Name
            Start-Sleep -Seconds 1
            $s2 = Get-NetAdapterStatistics -Name $netAdapter.Name
            $bwIn = [int64](($s2.ReceivedBytes - $s1.ReceivedBytes) * 8)
            $bwOut = [int64](($s2.SentBytes - $s1.SentBytes) * 8)
            if ($bwIn -lt 0) { $bwIn = 0 }
            if ($bwOut -lt 0) { $bwOut = 0 }
        }
    } catch { }

    return @{
        cpu_pct = $cpu
        mem_pct = $memPct
        bw_in_bps = $bwIn
        bw_out_bps = $bwOut
        rtt_ms = $rtt
    }
}

function Send-Heartbeat([string]$Token) {
    $net = Get-NetworkInfo
    $metrics = Get-Metrics
    $deviceId = ""
    if (Test-Path $Script:DeviceFile) {
        $deviceId = (Get-Content $Script:DeviceFile -Raw -Encoding UTF8).Trim()
    }

    $payload = @{
        hostname = $net.Hostname
        ip_address = $net.IpAddress
        mac_address = $net.MacAddress
        agent_version = $Script:AGENT_VERSION
        metrics = @{
            cpu_pct = $metrics.cpu_pct
            mem_pct = $metrics.mem_pct
            bw_in_bps = $metrics.bw_in_bps
            bw_out_bps = $metrics.bw_out_bps
        }
    }
    if ($null -ne $metrics.rtt_ms) {
        $payload.metrics.rtt_ms = $metrics.rtt_ms
    }
    if ($deviceId) {
        $payload.device_id = $deviceId
    }

    $result = Invoke-Api -Method Post -Path "/api/noc/heartbeat" -Token $Token -Body $payload
    if ($result.StatusCode -eq 200) {
        $body = $result.Body | ConvertFrom-Json
        $newId = $body.device_id
        if ($newId -and $newId -ne $deviceId) {
            Set-Content -Path $Script:DeviceFile -Value $newId -Encoding UTF8 -NoNewline -Force
        }
        Write-Ok "Heartbeat | cpu=$($metrics.cpu_pct)% mem=$($metrics.mem_pct)% rtt=$($metrics.rtt_ms)ms"
        Write-Log "NOC_HB host=$($net.Hostname) cpu=$($metrics.cpu_pct)% mem=$($metrics.mem_pct)%"
        return $true
    }
    if ($result.StatusCode -eq 401) {
        Write-Warn "Token expirado, renovando..."
        $newToken = Get-AgentToken
        Save-Token $newToken
        return Send-Heartbeat $newToken
    }
    Write-Err "Heartbeat HTTP $($result.StatusCode): $($result.Body)"
    return $false
}

function Invoke-RemoteAction([string]$ActionType, [object]$Payload) {
    $target = if ($Payload.target) { [string]$Payload.target } else { "8.8.8.8" }
    $output = ""
    $exitCode = 0

    switch ($ActionType) {
        "ping" {
            $output = & ping.exe -n 4 $target 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { $exitCode = $LASTEXITCODE }
        }
        "traceroute" {
            $output = & tracert.exe -h 20 $target 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { $exitCode = $LASTEXITCODE }
        }
        "restart_service" {
            $svc = if ($Payload.service) { [string]$Payload.service } else { "" }
            if ([string]::IsNullOrWhiteSpace($svc)) {
                $output = "Error: service requerido"
                $exitCode = 1
            } else {
                try {
                    Restart-Service -Name $svc -Force -ErrorAction Stop
                    $output = "Servicio '$svc' reiniciado."
                } catch {
                    $output = $_.Exception.Message
                    $exitCode = 1
                }
            }
        }
        "reboot" {
            $output = "Reinicio iniciado"
            return @{ Output = $output; ExitCode = 0; Reboot = $true }
        }
        default {
            $output = "Acción desconocida: $ActionType"
            $exitCode = 1
        }
    }

    return @{ Output = $output; ExitCode = $exitCode; Reboot = $false }
}

function Poll-Actions([string]$Token) {
    if (-not (Test-Path $Script:DeviceFile)) { return }
    $deviceId = (Get-Content $Script:DeviceFile -Raw -Encoding UTF8).Trim()
    if ([string]::IsNullOrWhiteSpace($deviceId)) { return }

    $result = Invoke-Api -Method Get -Path "/api/noc/agent/actions?device_id=$deviceId&status=pending" -Token $Token
    if ($result.StatusCode -ne 200) { return }

    $parsed = $result.Body | ConvertFrom-Json
    $actions = @($parsed.data)
    if ($actions.Count -eq 0) { return }

    foreach ($action in $actions) {
        $actionId = $action.id
        $actionType = $action.action_type
        $payload = if ($action.payload) { $action.payload } else { @{} }

        Invoke-Api -Method Patch -Path "/api/noc/actions/$actionId" -Token $Token -Body @{ status = "running" } | Out-Null

        $exec = Invoke-RemoteAction -ActionType $actionType -Payload $payload

        if ($exec.Reboot) {
            Invoke-Api -Method Patch -Path "/api/noc/actions/$actionId" -Token $Token -Body @{
                status = "done"
                output = $exec.Output
            } | Out-Null
            Write-Log "ACTION reboot"
            Restart-Computer -Force
            return
        }

        $finalStatus = if ($exec.ExitCode -eq 0) { "done" } else { "failed" }
        Invoke-Api -Method Patch -Path "/api/noc/actions/$actionId" -Token $Token -Body @{
            status = $finalStatus
            output = $exec.Output
        } | Out-Null
        Write-Log "ACTION $actionType → $finalStatus"
    }
}

function Install-ScheduledTask {
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        $scriptPath = $PSCommandPath
    }
    $scriptPath = (Resolve-Path $scriptPath).Path

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $start = (Get-Date).AddMinutes(1)
    $trigger = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::FromDays(3650))
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $Script:TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    } catch { }

    Register-ScheduledTask -TaskName $Script:TASK_NAME -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Ok "Tarea programada cada 5 min: $Script:TASK_NAME"
}

function Invoke-AgentRun {
    if (-not [Environment]::UserInteractive -and $Script:JITTER_MAX -gt 0) {
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum ($Script:JITTER_MAX + 1))
    }

    $token = Load-Token
    if (-not (Test-TokenValid $token)) {
        Write-Info "Obteniendo token..."
        $token = Get-AgentToken
        Save-Token $token
    }

    Send-Heartbeat $token | Out-Null
    Poll-Actions $token
}

function Invoke-AgentSetup {
    Write-Host ""
    Write-Host "obserLGCR — Agente NOC Windows v$($Script:AGENT_VERSION)" -ForegroundColor White
    Write-Host "  SO: $([Environment]::OSVersion.VersionString)" -ForegroundColor DarkGray
    Write-Host ""

    $url = Read-Host "  URL del servidor [$($Script:OBSERLGCR_URL)]"
    if ($url) { $Script:OBSERLGCR_URL = $url }

    $email = Read-Host "  Email del agente [noc-agent@obserlgcr.local]"
    $Script:AGENT_EMAIL = if ($email) { $email } else { "noc-agent@obserlgcr.local" }

    $secure = Read-Host "  Password del agente" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $Script:AGENT_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    $legacy = Read-Host "  Token estático legacy (vacío = JWT)"
    $Script:NOC_AGENT_TOKEN = if ($legacy) { $legacy } else { "" }

    Save-AgentEnv
    Write-Ok "Config en $Script:EnvFile"

    Write-Info "Autenticando..."
    $token = Get-AgentToken
    Save-Token $token

    try {
        Install-ScheduledTask
    } catch {
        Write-Warn "No se pudo registrar la tarea programada (ejecutar PowerShell como Administrador): $($_.Exception.Message)"
        Write-Warn "Puede programar manualmente: cada 5 min ejecutar este script."
    }

    Send-Heartbeat $token | Out-Null
    Write-Ok "Configuración completada."
}

function Invoke-AgentStatus {
    Write-Host ""
    Write-Host "Estado agente obserLGCR (Windows)" -ForegroundColor White
    Write-Info "Servidor : $($Script:OBSERLGCR_URL)"
    Write-Info "Config   : $Script:EnvFile"
    Write-Info "Email    : $(if ($Script:AGENT_EMAIL) { $Script:AGENT_EMAIL } else { '<no definido>' })"

    $token = Load-Token
    if (Test-TokenValid $token) { Write-Ok "Token válido" }
    else { Write-Warn "Sin token válido. Ejecutar: -Setup o -Renew" }

    $task = Get-ScheduledTask -TaskName $Script:TASK_NAME -ErrorAction SilentlyContinue
    if ($task) {
        Write-Ok "Tarea programada activa: $Script:TASK_NAME ($($task.State))"
    } else {
        Write-Warn "Sin tarea programada. Ejecutar: -Setup (como Administrador)"
    }

    if (Test-Path $Script:DeviceFile) {
        Write-Info "Device ID: $((Get-Content $Script:DeviceFile -Raw).Trim())"
    }
}

function Invoke-AgentRenew {
    $token = Get-AgentToken
    Save-Token $token
    Write-Ok "Token renovado."
}

function Invoke-AgentUninstall {
    try {
        Unregister-ScheduledTask -TaskName $Script:TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue
    } catch { }
    if (Test-Path $Script:BaseDir) {
        Remove-Item -Path $Script:BaseDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Agente desinstalado (archivos locales en $Script:BaseDir)."
}

Import-AgentEnv

if ($Help) {
    Write-Host "Uso: .\obserlgcr-noc-agent-windows.ps1 [-Setup|-Renew|-Status|-Uninstall|-Help]"
    exit 0
}

if ($Setup) { Invoke-AgentSetup; exit 0 }
if ($Renew) { Invoke-AgentRenew; exit 0 }
if ($Status) { Invoke-AgentStatus; exit 0 }
if ($Uninstall) { Invoke-AgentUninstall; exit 0 }

Invoke-AgentRun
