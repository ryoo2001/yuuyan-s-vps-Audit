$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'tunnel.mjs'
$status = Join-Path $PSScriptRoot 'status.json'
if (Test-Path -LiteralPath $status) {
    $state = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($state.pid)" -ErrorAction SilentlyContinue
    if ($process -and $process.CommandLine.Contains($script)) { Write-Host "审计数据库隧道已启动，状态：$($state.state)"; exit 0 }
}
$node = (Get-Command node.exe).Source
$child = Start-Process -FilePath $node -ArgumentList @('"' + $script + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
for ($i=0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if ($child.HasExited) { throw '隧道启动失败，请检查本地端口或主机认证。' }
    if (Test-Path -LiteralPath $status) {
        $state = Get-Content -LiteralPath $status -Raw | ConvertFrom-Json
        if ($state.pid -eq $child.Id -and $state.state -eq 'ready') { Write-Host '已连接：127.0.0.1:13306 → legacy-center SSH → MySQL'; exit 0 }
    }
}
throw '隧道仍在连接，状态见 client/status.json；未确认数据库可用。'
