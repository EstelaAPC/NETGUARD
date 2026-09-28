param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Scenario,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScenarioArgs
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

Push-Location $repoRoot
try {
    & docker compose exec -T lab-linux-01 netguard-lab-control $Scenario @ScenarioArgs
}
finally {
    Pop-Location
}
