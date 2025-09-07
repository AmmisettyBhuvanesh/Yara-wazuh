# ===================== CONFIG (edit these 3 only if needed) =====================
$WAZUH_MANAGER    = '135.13.19.196'         # <-- your Wazuh Manager IP/host
$WAZUH_GROUP      = 'default'               # <-- agent group
$VALHALLA_API_KEY = '<PUT_YOUR_API_KEY_HERE>' # <-- Valhalla API key (not 'demo')
$SCHEDULE_HOUR    = 2                       # daily refresh at local 02:00
# ===============================================================================

# --- Safety ---
$ErrorActionPreference = 'Stop'
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Please run this script as Administrator."
  }
}
function Enable-Tls12 {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
function Download-File($Url, $OutPath) {
  Write-Host "Downloading: $Url"
  Invoke-WebRequest -Uri $Url -OutFile $OutPath
}

# --- Install Wazuh Agent ---
function Install-WazuhAgent {
  $msi = Join-Path $env:TEMP 'wazuh-agent.msi'
  Download-File 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi' $msi
  $args = "/i `"$msi`" /q WAZUH_MANAGER='$WAZUH_MANAGER' WAZUH_AGENT_GROUP='$WAZUH_GROUP'"
  Write-Host "Installing Wazuh Agent..."
  Start-Process msiexec.exe -ArgumentList $args -Wait
  Remove-Item $msi -Force
}

# --- VC++ Redist (YARA dependency) ---
function Install-VCpp {
  $vc = Join-Path $env:TEMP 'vc_redist.x64.exe'
  Download-File 'https://aka.ms/vs/17/release/vc_redist.x64.exe' $vc
  Write-Host "Installing VC++ Redistributable..."
  Start-Process -FilePath $vc -ArgumentList '/install /quiet /norestart' -Wait
  Remove-Item $vc -Force
}

# --- YARA (Win64) ---  AUTO-DETECT LATEST FROM GITHUB
function Install-Yara {
  $zip = Join-Path $env:TEMP 'yara.zip'

  # Ask GitHub for the latest YARA release and pick a win64 asset
  $releasesApi = 'https://api.github.com/repos/VirusTotal/yara/releases/latest'
  $headers = @{ 'User-Agent' = 'PowerShell'; 'Accept' = 'application/vnd.github+json' }

  Write-Host "Querying latest YARA release from GitHub..."
  $latest = Invoke-RestMethod -Uri $releasesApi -Headers $headers

  $asset = $latest.assets | Where-Object {
    $_.name -match 'win64\.zip$'
  } | Select-Object -First 1

  if (-not $asset) {
    throw "Couldn't find a win64 ZIP in latest YARA release (${($latest.tag_name)})."
  }

  $yaraUrl = $asset.browser_download_url
  Write-Host "Downloading YARA: $($asset.name)"
  Download-File $yaraUrl $zip

  $tmp = Join-Path $env:TEMP 'yara_extracted'
  if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Remove-Item $zip -Force

  # Most zips contain 'yara.exe' at some depth; grab the first match
  $yaraExe = Get-ChildItem $tmp -Recurse -Filter 'yara.exe' | Select-Object -First 1
  if (-not $yaraExe) { throw "Could not locate YARA executable after extraction." }

  $base = "${env:ProgramFiles(x86)}\ossec-agent\active-response\bin\yara"
  New-Item -ItemType Directory -Force -Path $base | Out-Null
  Copy-Item $yaraExe.FullName (Join-Path $base 'yara64.exe') -Force

  $rulesDir = Join-Path $base 'rules'
  New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null

  return @{ YaraDir=$base; RulesDir=$rulesDir; YaraExe=(Join-Path $base 'yara64.exe') }
}

# --- yara.bat (active-response wrapper) ---
function Write-YaraBat {
  param([Parameter(Mandatory=$true)][string]$YaraExePath)
  $batPath = "${env:ProgramFiles(x86)}\ossec-agent\active-response\bin\yara.bat"
  $bat = @"
@echo off
setlocal EnableDelayedExpansion

reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT
if %OS%==32BIT (
  set OSSEC="%programfiles%\ossec-agent"
) else (
  set OSSEC="%programfiles(x86)%\ossec-agent"
)

set log_file_path=%OSSEC%\active-response\active-responses.log
set json_file_path=%OSSEC%\active-response\stdin.txt

for /F "tokens=* USEBACKQ" %%F in (`Powershell -Nop -C "(Get-Content '%json_file_path%'|ConvertFrom-Json).parameters.alert.syscheck.path"`) do (
  set syscheck_file_path=%%F
)
del /f %json_file_path%

set yara_exe_path="$YaraExePath"
set yara_rules_path=%OSSEC%\active-response\bin\yara\rules\yara_rules.yar

if exist "%yara_rules_path%" (
  for /f "delims=" %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - [valhalla] %%a >> %log_file_path%
  )
)

exit /b 0
"@
  Set-Content -Path $batPath -Value $bat -Encoding ASCII -Force
}

# --- Add Downloads folder to FIM via XML ---
function Ensure-FimDownloads {
  $conf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
  if (-not (Test-Path $conf)) { throw "ossec.conf not found at $conf" }
  [xml]$xml = Get-Content $conf

  $syscheck = $xml.ossec_config.syscheck
  if (-not $syscheck) {
    $syscheck = $xml.CreateElement('syscheck')
    $xml.ossec_config.AppendChild($syscheck) | Out-Null
  }
  $desired = 'C:\Users\*\Downloads'
  $existing = @()
  foreach ($node in $syscheck.SelectNodes('directories')) { $existing += $node.InnerText }

  if ($existing -notcontains $desired) {
    $node = $xml.CreateElement('directories')
    $attr = $xml.CreateAttribute('realtime'); $attr.Value = 'yes'
    $node.Attributes.Append($attr) | Out-Null
    $node.InnerText = $desired
    $syscheck.AppendChild($node) | Out-Null
    $xml.Save($conf)
    Write-Host "Added $desired to FIM (ossec.conf)."
  } else {
    Write-Host "FIM already contains $desired."
  }
}

# --- Valhalla pull (no Python, POST in PS) ---
function Download-ValhallaRules {
  param([Parameter(Mandatory=$true)][string]$ApiKey, [Parameter(Mandatory=$true)][string]$OutFile)

  $uri = 'https://valhalla.nextron-systems.com/api/v1/get'
  $body = @{ demo = 'demo'; apikey = $ApiKey; format = 'text' }
  Write-Host "Fetching latest YARA rules from Valhalla..."
  $resp = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -Headers @{
    'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    'Accept-Language' = 'en-US,en;q=0.5'
    'Referer' = 'https://valhalla.nextron-systems.com/'
    'DNT' = '1'
    'Upgrade-Insecure-Requests' = '1'
  }
  if (-not $resp.Content -or $resp.Content.Trim().Length -eq 0) { throw "Valhalla response was empty." }
  Set-Content -Path $OutFile -Value $resp.Content -Encoding UTF8
}

# --- Delete rule files older than N years (keeps main file) ---
function Cleanup-OldRules {
  param([Parameter(Mandatory=$true)][string]$RulesRoot, [int]$Years = 2)
  $cutoff = (Get-Date).AddYears(-$Years)
  $main = Join-Path $RulesRoot 'yara_rules.yar'
  $candidates = Get-ChildItem $RulesRoot -Filter *.yar -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $main }
  foreach ($f in $candidates) {
    if ($f.LastWriteTime -lt $cutoff) {
      try { Remove-Item $f.FullName -Force; Write-Host "Deleted old rule: $($f.Name)" }
      catch { Write-Warning "Failed to delete $($f.FullName): $($_.Exception.Message)" }
    }
  }
}

# --- Scheduled Task: daily Valhalla refresh + cleanup ---
function Register-RuleRefreshTask {
  param(
    [Parameter(Mandatory=$true)][string]$ApiKey,
    [Parameter(Mandatory=$true)][string]$RulesPath,
    [Parameter(Mandatory=$true)][string]$RulesRoot,
    [int]$Hour = 2
  )
  $taskName = 'Wazuh_Yara_Rules_Refresh'
  $refreshScriptPath = Join-Path $env:ProgramData 'Wazuh\refresh-yara-rules.ps1'
  New-Item -ItemType Directory -Force -Path (Split-Path $refreshScriptPath) | Out-Null

  $refreshScript = @"
`$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Valhalla pull
`$uri = 'https://valhalla.nextron-systems.com/api/v1/get'
`$body = @{ demo='demo'; apikey='$VALHALLA_API_KEY'; format='text' }
`$resp = Invoke-WebRequest -Uri `$uri -Method POST -Body `$body -ContentType 'application/x-www-form-urlencoded'
if (-not `$resp.Content -or `$resp.Content.Trim().Length -eq 0) { throw 'Valhalla response empty' }
Set-Content -Path '$RulesPath' -Value `$resp.Content -Encoding UTF8

# Cleanup > 2 years (except main file)
`$cutoff = (Get-Date).AddYears(-2)
`$main = Join-Path '$RulesRoot' 'yara_rules.yar'
`$cand = Get-ChildItem '$RulesRoot' -Filter *.yar -File -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -ne `$main }
foreach (`$f in `$cand) {
  if (`$f.LastWriteTime -lt `$cutoff) {
    try { Remove-Item `$f.FullName -Force } catch { Write-Warning "Cleanup failed: `$($_.Exception.Message)" }
  }
}

# Optional: restart agent
# Restart-Service -Name WazuhSvc -Force
"@
  Set-Content -Path $refreshScriptPath -Value $refreshScript -Encoding UTF8 -Force

  $time = (Get-Date).Date.AddHours($Hour)
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$refreshScriptPath`""
  $trigger = New-ScheduledTaskTrigger -Daily -At $time
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

  if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  }
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
  Write-Host "Scheduled daily rule refresh task '$taskName' at $($time.ToShortTimeString())"
}

# ============================== MAIN ==========================================
try {
  if ([string]::IsNullOrWhiteSpace($VALHALLA_API_KEY) -or $VALHALLA_API_KEY -eq '<PUT_YOUR_API_KEY_HERE>') {
    throw "VALHALLA_API_KEY is not set inside the script. Edit the script and place your real key."
  }

  Assert-Admin
  Enable-Tls12

  Install-WazuhAgent
  Install-VCpp

  $y = Install-Yara
  Write-YaraBat -YaraExePath $y.YaraExe

  # Initial Valhalla pull
  $rulesFile = Join-Path $y.RulesDir 'yara_rules.yar'
  Download-ValhallaRules -ApiKey $VALHALLA_API_KEY -OutFile $rulesFile
  Write-Host "YARA rules saved: $rulesFile"

  # Ensure FIM
  Ensure-FimDownloads

  # Initial cleanup (2 years)
  Cleanup-OldRules -RulesRoot $y.RulesDir -Years 2

  # Schedule daily refresh
  Register-RuleRefreshTask -ApiKey $VALHALLA_API_KEY -RulesPath $rulesFile -RulesRoot $y.RulesDir -Hour $SCHEDULE_HOUR

  # Restart agent
  Write-Host "Restarting Wazuh Agent..."
  Restart-Service -Name WazuhSvc -Force

  Write-Host "`nAll steps completed successfully ✅"
}
catch {
  Write-Error "FAILED: $($_.Exception.Message)"
  exit 1
}
# ==============================================================================
