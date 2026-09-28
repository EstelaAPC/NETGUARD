param(
    [string]$HostName = "lab-linux-01",
    [string]$HostIp = "172.30.10.10"
)

$arguments = @(
    "compose", "exec", "-T", "db",
    "psql",
    "-U", "netguard",
    "-d", "netguard",
    "-v", "ON_ERROR_STOP=1",
    "-v", "demo_host_name=$HostName",
    "-v", "demo_host_ip=$HostIp",
    "-f", "/opt/netguard-sql/demo_reset_lab_linux_01.sql"
)

& docker @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
