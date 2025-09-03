# Run as Administrator
# --- Step 1: Wazuh Agent ---
Write-Host "Installing Wazuh Agent..."
$wazuhInstaller = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi" -OutFile $wazuhInstaller
Start-Process msiexec.exe -ArgumentList "/i `"$wazuhInstaller`" /q WAZUH_MANAGER='135.13.19.196' WAZUH_AGENT_GROUP='default'" -Wait

# --- Step 2: Python ---
Write-Host "Installing Python..."
$pythonInstaller = "$env:TEMP\python-installer.exe"
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe" -OutFile $pythonInstaller
& $pythonInstaller /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1
# reload PATH so we can use python immediately
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

# --- Step 3: VC++ ---
Write-Host "Installing VC++ Redistributable..."
$vcInstaller = "$env:TEMP\vc_redist.x64.exe"
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcInstaller
& $vcInstaller /install /quiet /norestart

# --- Step 4: valhallaAPI ---
Write-Host "Installing valhallaAPI..."
python -m ensurepip --upgrade
python -m pip install --upgrade pip
python -m pip install valhallaAPI

# --- Step 5: YARA ---
Write-Host "Downloading and extracting YARA..."
# get latest YARA win64 asset dynamically
$release = Invoke-RestMethod "https://api.github.com/repos/VirusTotal/yara/releases/latest"
$asset = $release.assets | Where-Object { $_.name -match "win64.zip" } | Select-Object -First 1
$yaraZip = "$env:TEMP\yara.zip"
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $yaraZip
Expand-Archive -Path $yaraZip -DestinationPath "$env:TEMP\yara" -Force
Remove-Item $yaraZip -Force
$yaraExe = Get-ChildItem "$env:TEMP\yara" -Recurse -Filter "yara*.exe" | Select-Object -First 1
if ($yaraExe) {
    New-Item -ItemType Directory -Force -Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara" | Out-Null
    Copy-Item $yaraExe.FullName "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe" -Force
} else {
    Write-Host "YARA executable not found after extraction!"
}

# --- Step 6: YARA rules from your repo ---
Write-Host "Downloading YARA rules..."
New-Item -ItemType Directory -Force -Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules" | Out-Null
$rulesUrl = "https://raw.githubusercontent.com/AmmisettyBhuvanesh/Yara-wazuh/main/yara_rules.yar"
try {
    Invoke-WebRequest -Uri $rulesUrl -OutFile "$env:TEMP\yara_rules.yar" -ErrorAction Stop
    Copy-Item "$env:TEMP\yara_rules.yar" "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" -Force
} catch {
    Write-Host "Could not download YARA rules from $rulesUrl"
}

# --- Step 7: Create yara.bat (unchanged) ---
Write-Host "Creating yara.bat..."
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
set input=
for /f "delims=" %%a in ('PowerShell -command "$logInput = Read-Host; Write-Output $logInput"') do (
    set input=%%a
)
set json_file_path="C:\Program Files (x86)\ossec-agent\active-response\stdin.txt"
set syscheck_file_path=
echo %input% > %json_file_path%
for /F "tokens=* USEBACKQ" %%F in (`Powershell -Nop -C "(Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\stdin.txt'|ConvertFrom-Json).parameters.alert.syscheck.path"`) do (
set syscheck_file_path=%%F
)
del /f %json_file_path%
set yara_exe_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe"
set yara_rules_path="C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar"
echo %syscheck_file_path% >> %log_file_path%
for /f "delims=" %%a in ('powershell -command "& \"%yara_exe_path%\" \"%yara_rules_path%\" \"%syscheck_file_path%\""') do (
    echo wazuh-yara: INFO - Scan result: %%a >> %log_file_path%
)
exit /b
"@
Set-Content -Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat" -Value $yaraBat -Encoding ASCII -Force

# --- Step 8: Add Downloads folder ---
Write-Host "Adding Downloads folder to ossec.conf..."
$userName = $env:USERNAME
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$downloadsDir = "<directories realtime=`"yes`">C:\Users\$userName\Downloads</directories>"
if (-not (Select-String -Path $ossecConf -Pattern "C:\\Users\\$userName\\Downloads" -Quiet)) {
    (Get-Content $ossecConf) -replace "(?<=</directories>)", "`n$downloadsDir" | Set-Content $ossecConf
}

# --- Step 9: Restart Wazuh Agent ---
Write-Host "Restarting Wazuh Agent..."
Restart-Service -Name WazuhSvc -Force
Write-Host "All steps completed."
