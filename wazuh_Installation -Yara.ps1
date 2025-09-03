# Requires admin
# Step 1: Install Wazuh Agent
Write-Host "Installing Wazuh Agent..."
$wazuhInstaller = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi" -OutFile $wazuhInstaller
Start-Process msiexec.exe -ArgumentList "/i `"$wazuhInstaller`" /q WAZUH_MANAGER='135.13.19.196' WAZUH_AGENT_GROUP='default'" -Wait

# Step 2: Install Python
Write-Host "Installing Python..."
$pythonInstaller = "$env:TEMP\python-installer.exe"
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe" -OutFile $pythonInstaller
& $pythonInstaller /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1

# Step 3: Install Visual C++ Redistributable
Write-Host "Installing VC++ Redistributable..."
$vcInstaller = "$env:TEMP\vc_redist.x64.exe"
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcInstaller
& $vcInstaller /install /quiet /norestart

# Step 4: Install valhallaAPI via Python
Write-Host "Installing valhallaAPI module..."
python -m ensurepip --upgrade
python -m pip install --upgrade pip
python -m pip install valhallaAPI

# Step 5: Download & Extract YARA dynamically
Write-Host "Downloading and extracting YARA..."
$yaraZip = "$env:TEMP\yara.zip"
Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.2.3/yara-v4.2.3-2029-win64.zip" -OutFile $yaraZip
Expand-Archive -Path $yaraZip -DestinationPath "$env:TEMP\yara" -Force
Remove-Item $yaraZip -Force
$yaraExe = Get-ChildItem "$env:TEMP\yara" -Recurse -Filter "yara64.exe" | Select-Object -First 1
if ($yaraExe) {
    New-Item -ItemType Directory -Force -Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara" | Out-Null
    Copy-Item $yaraExe.FullName "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\yara64.exe" -Force
} else {
    Write-Host "YARA executable not found after extraction!"
}

# Step 6: Download YARA rules from your repo
Write-Host "Downloading YARA rules..."
New-Item -ItemType Directory -Force -Path "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules" | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/AmmisettyBhuvanesh/Yara-wazuh/main/yara_rules.yar" -OutFile "$env:TEMP\yara_rules.yar"
Copy-Item "$env:TEMP\yara_rules.yar" "C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\yara_rules.yar" -Force

# Step 7: Create yara.bat
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

# Step 8: Add Downloads folder to ossec.conf
Write-Host "Adding Downloads folder to ossec.conf..."
$userName = $env:USERNAME
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$downloadsDir = "<directories realtime=`"yes`">C:\Users\$userName\Downloads</directories>"
if (-not (Select-String -Path $ossecConf -Pattern "C:\\Users\\$userName\\Downloads" -Quiet)) {
    (Get-Content $ossecConf) -replace "(?<=</directories>)", "`n$downloadsDir" | Set-Content $ossecConf
}

# Step 9: Restart Wazuh agent (service is WazuhSvc)
Write-Host "Restarting Wazuh Agent..."
Restart-Service -Name WazuhSvc -Force
Write-Host "All steps completed."
