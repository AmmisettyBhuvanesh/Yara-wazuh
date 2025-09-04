# Requires: Run as Administrator

# --- Step 1: Wazuh Agent ---
Write-Host "Installing Wazuh Agent..."
$wazuhInstaller = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi" -OutFile $wazuhInstaller
Start-Process msiexec.exe -ArgumentList "/i `"$wazuhInstaller`" /q WAZUH_MANAGER='135.13.19.196' WAZUH_AGENT_GROUP='default'" -Wait
Remove-Item $wazuhInstaller -Force

# --- Step 2: Python ---
Write-Host "Installing Python..."
$pythonInstaller = "$env:TEMP\python-installer.exe"
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe" -OutFile $pythonInstaller
Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1" -Wait
Remove-Item $pythonInstaller -Force

# Wait for python.exe to appear
Write-Host "Checking Python installation..."
$pythonPath = $null
$timeout = (Get-Date).AddMinutes(2)
do {
    # System-wide
    $pythonExe = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pythonExe) { $pythonPath = $pythonExe.Source }

    # User/local
    if (-not $pythonPath) {
        $userPythonDir = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Directory -Filter "Python*" -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($userPythonDir) { $pythonPath = Join-Path $userPythonDir.FullName "python.exe" }
    }

    # py.exe fallback
    if (-not $pythonPath) {
        $pyExe = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($pyExe) { $pythonPath = $pyExe.Source }
    }

    if (-not $pythonPath -or -not (Test-Path $pythonPath)) { Start-Sleep -Seconds 5 }
} until ((Test-Path $pythonPath) -or ((Get-Date) -gt $timeout))

if (-not (Test-Path $pythonPath)) {
    throw "Could not locate python.exe after installation (timeout)."
}
Write-Host "Using Python at $pythonPath"

# --- Step 3: VC++ ---
Write-Host "Installing VC++ Redistributable..."
$vcInstaller = "$env:TEMP\vc_redist.x64.exe"
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcInstaller
Start-Process -FilePath $vcInstaller -ArgumentList "/install /quiet /norestart" -Wait
Remove-Item $vcInstaller -Force

# --- Step 4: valhallaAPI ---
Write-Host "Installing valhallaAPI..."
& $pythonPath -m ensurepip --upgrade
& $pythonPath -m pip install --upgrade pip
& $pythonPath -m pip install valhallaAPI

# --- Step 5: YARA ---
Write-Host "Downloading and extracting YARA..."
$yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.2.3/yara-4.2.3-2029-win64.zip"
$yaraZip = "$env:TEMP\yara.zip"
Invoke-WebRequest -Uri $yaraUrl -OutFile $yaraZip

$yaraTempDir = "$env:TEMP\yara"
if (Test-Path $yaraTempDir) { Remove-Item $yaraTempDir -Recurse -Force }
Expand-Archive -Path $yaraZip -DestinationPath $yaraTempDir -Force
Remove-Item $yaraZip -Force

$yaraExe = Get-ChildItem $yaraTempDir -Recurse -Filter "yara*.exe" | Select-Object -First 1
$targetYaraDir = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
if (-not (Test-Path $targetYaraDir)) { New-Item -ItemType Directory -Force -Path $targetYaraDir | Out-Null }
if ($yaraExe) {
    Copy-Item $yaraExe.FullName (Join-Path $targetYaraDir "yara64.exe") -Force
    Write-Host "YARA copied to $targetYaraDir"
} else {
    Write-Warning "YARA executable not found after extraction!"
}

# --- Step 6: YARA rules ---
Write-Host "Downloading YARA rules..."
$rulesUrl = "https://raw.githubusercontent.com/AmmisettyBhuvanesh/Yara-wazuh/main/yara_rules.yar"
$rulesDir = Join-Path $targetYaraDir "rules"
New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
try {
    $tempRules = Join-Path $env:TEMP "yara_rules.yar"
    Invoke-WebRequest -Uri $rulesUrl -OutFile $tempRules -ErrorAction Stop
    Copy-Item $tempRules (Join-Path $rulesDir "yara_rules.yar") -Force
    Write-Host "YARA rules saved to $rulesDir"
} catch {
    Write-Warning "Could not download YARA rules from $rulesUrl"
}

# --- Step 7: Create yara.bat ---
Write-Host "Creating yara.bat..."
$yaraBatPath = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat"
$yaraBat = @"
@echo off
setlocal enableDelayedExpansion
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && SET OS=32BIT || SET OS=64BIT
if %OS%==32BIT (
    SET log_file_path="%programfiles%\ossec-agent\active-response\active-responses.log"
)
if %OS%==64BIT (
    SET log_file_path="%programfiles(x86)%\ossec-agent\active-response\active-responses.log"
)
set json_file_path="%programfiles(x86)%\ossec-agent\active-response\stdin.txt"
for /F "tokens=* USEBACKQ" %%F in (`Powershell -Nop -C "(Get-Content '%json_file_path%'|ConvertFrom-Json).parameters.alert.syscheck.path"`) do (
set syscheck_file_path=%%F
)
del /f %json_file_path%
set yara_exe_path="%programfiles(x86)%\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="%programfiles(x86)%\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
for /f "delims=" %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - Scan result: %%a >> %log_file_path%
)
exit /b
"@
Set-Content -Path $yaraBatPath -Value $yaraBat -Encoding ASCII -Force

# --- Step 8: Add Downloads folder to ossec.conf ---
Write-Host "Adding Downloads folder to ossec.conf..."
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
    $downloadsDir = '  <directories realtime="yes">C:\Users\*\Downloads</directories>'
    if (-not (Select-String -Path $ossecConf -Pattern "C:\\Users\\.*\\Downloads" -Quiet)) {
        (Get-Content $ossecConf) -replace "(?<=</directories>)", "`n$downloadsDir" |
            Set-Content $ossecConf
        Write-Host "Added Downloads directory to ossec.conf"
    }
} else {
    Write-Warning "ossec.conf not found at $ossecConf"
}

# --- Step 9: Restart Wazuh Agent ---
Write-Host "Restarting Wazuh Agent..."
Restart-Service -Name WazuhSvc -Force
Write-Host "All steps completed."
