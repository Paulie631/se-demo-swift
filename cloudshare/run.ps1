<#
  Amazon Quick SE demo kit - runner for a CloudShare (or any) Windows VM.

  The console on your laptop starts this through the CloudShare API. You can also run it by hand on the VM:
    powershell -ExecutionPolicy Bypass -File C:\SE-Demo\run.ps1 -Scenarios dlp,upload

  First run installs uv, Python 3.12 and the kit under C:\SE-Demo (a minute or two). Every run refreshes the kit
  from GitHub, then sends the demo traffic through this VM's Client Connector. All data is synthetic.
  Last line of output: QK_RESULT {json} - that's what the console reads.

  -Schedule -Every 60   register a task that sends a small batch every N minutes (keeps dashboards fresh)
  -Unschedule           remove that task
#>
param(
  [string]$Scenarios = "visibility,dlp,upload",
  [int]$Loops = 1,
  [string]$Region = "",
  [string]$Repo = "Paulie631/se-demo-swift",
  [string]$Ref = "main",
  [switch]$Schedule,
  [int]$Every = 60,
  [switch]$Unschedule
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Task = "SE-Demo Quick traffic"
$Base = "C:\SE-Demo"
$Kit = "$Base\quick-kit"
$Log = "$Base\quick-runner.log"
New-Item -ItemType Directory -Force -Path $Base, $Kit | Out-Null

function Result($obj) { "QK_RESULT " + ($obj | ConvertTo-Json -Compress -Depth 6) }
function Note($m) { $line = "$(Get-Date -Format s) $m"; Add-Content -Path $Log -Value $line; Write-Output $line }

try {
  if ($Unschedule) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Note "Removed scheduled task '$Task'"
    Result @{ ok = $true; unscheduled = $true }
    exit 0
  }

  if ($Schedule) {
    Copy-Item -Force $PSCommandPath "$Base\run.ps1" -ErrorAction SilentlyContinue
    $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$Base\run.ps1`" -Scenarios `"$Scenarios`" -Loops 1 -Repo `"$Repo`" -Ref `"$Ref`""
    if ($Region) { $taskArgs += " -Region `"$Region`"" }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Every)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Note "Scheduled '$Task' every $Every minutes ($Scenarios)"
    Result @{ ok = $true; scheduled = $true; every = $Every; scenarios = $Scenarios }
    exit 0
  }

  # uv (first run only), kept under C:\SE-Demo so SYSTEM and interactive users share it
  $uvDir = "$Base\uv"; $uv = "$uvDir\uv.exe"
  if (-not (Test-Path $uv)) {
    Note "Installing uv..."
    $env:UV_INSTALL_DIR = $uvDir; $env:UV_NO_MODIFY_PATH = "1"
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
  }
  if (-not (Test-Path $uv)) { throw "uv didn't install. Does this VM have internet access through Client Connector?" }

  # refresh the kit from GitHub
  $zip = "$env:TEMP\quick-kit.zip"; $tmp = "$env:TEMP\quick-kit-src"
  Invoke-WebRequest -UseBasicParsing "https://codeload.github.com/$Repo/zip/$Ref" -OutFile $zip
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
  Expand-Archive -Force -Path $zip -DestinationPath $tmp
  $src = Get-ChildItem $tmp | Select-Object -First 1
  Copy-Item -Recurse -Force "$($src.FullName)\*" $Kit

  $env:UV_SYSTEM_CERTS = "1"; $env:UV_NATIVE_TLS = "1"; $env:PYTHONUTF8 = "1"
  $env:UV_CACHE_DIR = "$Base\uv-cache"; $env:UV_PYTHON_INSTALL_DIR = "$Base\python"
  $env:QUICK_KIT_HOME = "$Base\quick-home"

  $kargs = @("run", "--quiet", "--python", "3.12", "--script", "$Kit\quick_kit.py", "traffic",
             "--scenarios", $Scenarios, "--loops", "$Loops", "--json")
  if ($Region) { $kargs += @("--region", $Region) }
  Note "Sending traffic: $Scenarios x $Loops"
  $out = & $uv @kargs 2>&1 | ForEach-Object { "$_" }
  $out | Write-Output
  if ($LASTEXITCODE -ne 0 -and -not ($out | Where-Object { $_ -like "QK_RESULT *" })) {
    throw "The kit exited with code $LASTEXITCODE"
  }
  exit $LASTEXITCODE
}
catch {
  Note "ERROR: $($_.Exception.Message)"
  Result @{ ok = $false; error = "$($_.Exception.Message)" }
  exit 1
}
