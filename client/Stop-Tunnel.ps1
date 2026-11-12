$ErrorActionPreference = 'Stop'
$status = Join-Path $PSScriptRoot 'status.json'
if (!(Test-Path -LiteralPath $status)) { exit 0 }
$state = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$($state.pid)" -ErrorAction SilentlyContinue
$script = Join-Path $PSScriptRoot 'tunnel.mjs'
if ($process -and $process.CommandLine.Contains($script)) {
    Stop-Process -Id $state.pid
    Write-Host '审计数据库隧道已关闭。'
} else { Write-Host '没有找到本任务的隧道进程，未停止其他进程。' }
