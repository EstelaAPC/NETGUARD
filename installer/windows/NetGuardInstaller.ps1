param(
    [switch]$Quiet
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidate = Resolve-Path (Join-Path $scriptDir "..\..") -ErrorAction SilentlyContinue
    if ($candidate -and (Test-Path (Join-Path $candidate "docker-compose.yml"))) {
        return $candidate.Path
    }
    if (Test-Path (Join-Path $scriptDir "docker-compose.yml")) {
        return $scriptDir
    }
    return $scriptDir
}

$RepoRoot = Get-RepoRoot

function New-Label($text, $x, $y, $w = 180) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $text
    $label.Location = New-Object System.Drawing.Point($x, $y)
    $label.Size = New-Object System.Drawing.Size($w, 20)
    return $label
}

function New-TextBox($text, $x, $y, $w = 390) {
    $box = New-Object System.Windows.Forms.TextBox
    $box.Text = $text
    $box.Location = New-Object System.Drawing.Point($x, $y)
    $box.Size = New-Object System.Drawing.Size($w, 24)
    return $box
}

function Add-Log($message) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    $script:LogBox.AppendText("[$timestamp] $message`r`n")
    $script:LogBox.SelectionStart = $script:LogBox.Text.Length
    $script:LogBox.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Invoke-Logged($file, $arguments, $workdir) {
    Add-Log "> $file $arguments"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $file
    $psi.Arguments = $arguments
    $psi.WorkingDirectory = $workdir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($stdout.Trim()) { Add-Log $stdout.Trim() }
    if ($stderr.Trim()) { Add-Log $stderr.Trim() }
    if ($process.ExitCode -ne 0) {
        throw "$file saiu com codigo $($process.ExitCode)"
    }
}

function Test-Docker {
    Invoke-Logged "docker" "version" $RepoRoot
    Invoke-Logged "docker" "compose version" $RepoRoot
}

function Write-NetGuardEnv($installPath, $publicUrl, $grafanaUrl, $ollamaUrl) {
    $envPath = Join-Path $installPath ".env"
    $content = @"
POSTGRES_USER=netguard
POSTGRES_PASSWORD=netguard
POSTGRES_DB=netguard
DATABASE_URL=postgresql://netguard:netguard@db:5432/netguard

NETGUARD_PUBLIC_URL=$publicUrl
GRAFANA_PUBLIC_URL=$grafanaUrl
GRAFANA_ORG_ID=1
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin
NETGUARD_DEFAULT_USER_PASSWORD=change-me-123
NETGUARD_CORS_ORIGINS=https://localhost:8081,https://127.0.0.1:8081,http://localhost:8081,http://127.0.0.1:8081
VITE_API_URL=/api

OLLAMA_BASE_URL=$ollamaUrl
OLLAMA_MODEL=llama3.1:8b
OLLAMA_TIMEOUT_SEC=180
OLLAMA_NUM_GPU=0
AI_INSIGHTS_TTL_HOURS=8

POLL_INTERVAL=30
SNMP_INTERVAL_SEC=30
DEFAULT_COLLECTION_TIMEOUT_SEC=1
DEFAULT_COLLECTION_RETRIES=1

AVAILABILITY_ALERTS_ENABLED=true
AVAILABILITY_ICMP_STALE_MULTIPLIER=4
AVAILABILITY_SNMP_STALE_MULTIPLIER=4
AVAILABILITY_SYSLOG_STALE_SEC=300
AVAILABILITY_HOST_DOWN_SAMPLES=2
AVAILABILITY_MIN_STALE_SEC=60

HOUSEKEEPER_ENABLED=true
HOUSEKEEPER_INTERVAL_SEC=3600
HOUSEKEEPER_BATCH_ROWS=50000
RETENTION_METRICS_DAYS=30
RETENTION_SYSLOG_DAYS=14
RETENTION_ANOMALY_SCORES_DAYS=30
RETENTION_AI_INSIGHTS_DAYS=30
RETENTION_NOTIFICATIONS_DAYS=180
RETENTION_RESOLVED_INCIDENTS_DAYS=180

ALERT_WEBHOOK_ENABLED=false
WEBHOOK_PROVIDER=discord
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_PARSE_MODE=
"@
    Set-Content -LiteralPath $envPath -Value $content -Encoding UTF8
    Add-Log ".env criado em $envPath"
}

function Copy-NetGuardPackage($installPath) {
    New-Item -ItemType Directory -Force -Path $installPath | Out-Null
    $excludeDirs = ".git node_modules __pycache__ dist .venv venv infra_dbdata infra_grafdata"
    $args = "`"$RepoRoot`" `"$installPath`" /MIR /XD $excludeDirs /XF *.pyc"
    Add-Log "Copiando pacote para $installPath"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "robocopy"
    $psi.Arguments = $args
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($stdout.Trim()) { Add-Log $stdout.Trim() }
    if ($stderr.Trim()) { Add-Log $stderr.Trim() }
    if ($process.ExitCode -gt 7) {
        throw "Robocopy falhou com codigo $($process.ExitCode)"
    }
}

function Install-NetGuard {
    $installPath = $script:InstallPathBox.Text.Trim()
    $publicUrl = $script:PublicUrlBox.Text.Trim()
    $grafanaUrl = $script:GrafanaUrlBox.Text.Trim()
    $ollamaUrl = $script:OllamaUrlBox.Text.Trim()
    if (-not $installPath) { throw "Informe o caminho de instalacao." }
    Test-Docker
    Copy-NetGuardPackage $installPath
    Write-NetGuardEnv $installPath $publicUrl $grafanaUrl $ollamaUrl
    Invoke-Logged "docker" "compose -p netguard up -d --build" $installPath
    Add-Log "NetGuard instalado/atualizado. Acesse $publicUrl"
}

function Start-NetGuard {
    $installPath = $script:InstallPathBox.Text.Trim()
    Invoke-Logged "docker" "compose -p netguard up -d" $installPath
}

function Stop-NetGuard {
    $installPath = $script:InstallPathBox.Text.Trim()
    Invoke-Logged "docker" "compose -p netguard stop" $installPath
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "NetGuard Installer"
$form.Size = New-Object System.Drawing.Size(760, 560)
$form.StartPosition = "CenterScreen"

$form.Controls.Add((New-Label "Pasta de instalacao" 18 22))
$script:InstallPathBox = New-TextBox "C:\ProgramData\NetGuard" 180 18 520
$form.Controls.Add($script:InstallPathBox)

$form.Controls.Add((New-Label "URL publica" 18 58))
$script:PublicUrlBox = New-TextBox "https://localhost:8081" 180 54 520
$form.Controls.Add($script:PublicUrlBox)

$form.Controls.Add((New-Label "Grafana URL" 18 94))
$script:GrafanaUrlBox = New-TextBox "http://localhost:3000" 180 90 520
$form.Controls.Add($script:GrafanaUrlBox)

$form.Controls.Add((New-Label "Ollama URL" 18 130))
$script:OllamaUrlBox = New-TextBox "http://host.docker.internal:11434" 180 126 520
$form.Controls.Add($script:OllamaUrlBox)

$buttons = @(
    @{ Text = "Checar Docker"; X = 18; Action = { Test-Docker; Add-Log "Docker ok." } },
    @{ Text = "Instalar/Atualizar"; X = 150; Action = { Install-NetGuard } },
    @{ Text = "Iniciar"; X = 310; Action = { Start-NetGuard } },
    @{ Text = "Parar"; X = 400; Action = { Stop-NetGuard } },
    @{ Text = "Abrir"; X = 490; Action = { Start-Process $script:PublicUrlBox.Text.Trim() } }
)

foreach ($item in $buttons) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $item.Text
    $button.Location = New-Object System.Drawing.Point($item.X, 168)
    $button.Size = New-Object System.Drawing.Size(122, 32)
    $button.Add_Click({
        param($sender, $eventArgs)
        try {
            & $sender.Tag
        } catch {
            Add-Log "ERRO: $($_.Exception.Message)"
        }
    })
    $button.Tag = $item.Action
    $form.Controls.Add($button)
}

$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Location = New-Object System.Drawing.Point(18, 218)
$script:LogBox.Size = New-Object System.Drawing.Size(700, 280)
$script:LogBox.Multiline = $true
$script:LogBox.ScrollBars = "Vertical"
$script:LogBox.ReadOnly = $true
$script:LogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($script:LogBox)

Add-Log "Fonte do pacote: $RepoRoot"
Add-Log "Use Instalar/Atualizar para aplicar o NetGuard completo via Docker Compose."

if ($Quiet) {
    Install-NetGuard
} else {
    [void]$form.ShowDialog()
}
