# RAKSHA AI — one-click Windows install that keeps everything on D: or E:.
#
# Easiest: download deploy/windows/RAKSHA-Setup.bat and double-click it. Or paste into PowerShell:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.ps1)))
#
# What it does:
#   1. picks D: or E: (whichever has more free space; -Drive overrides) and works under <drive>:\RAKSHA
#   2. makes sure WSL2 is present (asks for Administrator once, and a reboot, if it is not)
#   3. creates a private Ubuntu 24.04 system named "RAKSHA" whose disk lives in <drive>:\RAKSHA\wsl
#      — nothing big is written to C:
#   4. lets that system reach the Ollama you run on Windows (mirrored networking on Windows 11)
#   5. inside it, runs deploy/laptop-bootstrap.sh: toolchains, scanners, the repository, the
#      virtualenv, the offline vulnerability database, then the checks
#   6. asks which model provider + model to use (any time later: 'RAKSHA Set Model.bat')
#   7. writes double-click launchers into <drive>:\RAKSHA (console, shell, change model, update)
#
# Parameters: -Drive D  -Model "gpt-oss:120b-cloud" (an Ollama model; skips the provider menu)  -SkipTests
# Needs ~6 GB free on the chosen drive and an internet connection for the install only.

param(
    [string]$Drive = "",
    [string]$Model = "",
    [switch]$SkipTests
)

$ErrorActionPreference = "Continue"      # native tools write to stderr; failures are checked explicitly
$ProgressPreference = "SilentlyContinue"         # Invoke-WebRequest is 10x slower with the progress bar
$env:WSL_UTF8 = "1"                               # wsl.exe prints UTF-8 instead of UTF-16
$branch = "claude/magical-mayer-gs2xno"
$raw = "https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/$branch"
$rootfsUrl = "https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz"
$distro = "RAKSHA"

function Say($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Wsl-Distros { @(wsl.exe -l -q 2>$null | ForEach-Object { ($_ -replace "`0", "").Trim() } | Where-Object { $_ }) }
function Download($url, $out) {
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) { curl.exe -fL --retry 3 -o $out $url; if ($LASTEXITCODE -ne 0) { throw "download failed: $url" } }
    else { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out }
}

# ---- 1. drive ----------------------------------------------------------------------------
if ($Drive) { $d = Get-PSDrive ($Drive.TrimEnd(':')) }
else {
    $d = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -in @("D", "E") -and $_.Free } |
         Sort-Object Free -Descending | Select-Object -First 1
    if (-not $d) { Write-Host "No D: or E: drive found. Re-run with -Drive <letter>."; exit 1 }
}
$base = "$($d.Name):\RAKSHA"
$freeGB = [math]::Round($d.Free / 1GB, 1)
Say "Installing under $base  ($freeGB GB free)"
if ($d.Free -lt 6GB) { Write-Host "Warning: under 6 GB free on $($d.Name):. The install may run out of space." -ForegroundColor Yellow }
New-Item -ItemType Directory -Force -Path "$base\cache", "$base\wsl" | Out-Null

# ---- 2. WSL2 -----------------------------------------------------------------------------
wsl.exe --status *> $null
if ($LASTEXITCODE -ne 0) {
    Say "WSL is not enabled yet. Windows will ask for Administrator permission to turn it on."
    Start-Process wsl.exe -ArgumentList "--install --no-distribution" -Verb RunAs -Wait
    Write-Host ""
    Write-Host "WSL has been enabled. RESTART the laptop, then run RAKSHA-Setup.bat again." -ForegroundColor Yellow
    exit 0
}
wsl.exe --update *> $null                          # newest WSL; harmless if already current
wsl.exe --set-default-version 2 *> $null

# ---- 3. networking so the RAKSHA system can reach Ollama on Windows ----------------------
$build = [Environment]::OSVersion.Version.Build
$cfg = Join-Path $env:USERPROFILE ".wslconfig"
$restartWsl = $false
if ($build -ge 22621) {
    $text = if (Test-Path $cfg) { Get-Content $cfg -Raw } else { "" }
    if ($text -notmatch "networkingMode") {
        if ($text -match "\[wsl2\]") { $text = $text -replace "\[wsl2\]", "[wsl2]`r`nnetworkingMode=mirrored" }
        else { $text = $text + "`r`n[wsl2]`r`nnetworkingMode=mirrored`r`n" }
        Set-Content -Path $cfg -Value $text -Encoding ASCII
        $restartWsl = $true
        Write-Host "Enabled mirrored networking in $cfg (WSL sees Windows' 127.0.0.1)."
    }
} else {
    # Windows 10: no mirrored mode. Ollama must listen beyond loopback for WSL to reach it.
    if (-not [Environment]::GetEnvironmentVariable("OLLAMA_HOST", "User")) {
        [Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")
        Write-Host "Windows 10: set OLLAMA_HOST=0.0.0.0:11434 so WSL can reach Ollama. Quit and restart Ollama once." -ForegroundColor Yellow
    }
}
# Local Ollama models (if you ever pull one) go to the big drive, not C:
if (-not [Environment]::GetEnvironmentVariable("OLLAMA_MODELS", "User")) {
    New-Item -ItemType Directory -Force -Path "$base\ollama-models" | Out-Null
    [Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "$base\ollama-models", "User")
    Write-Host "Set OLLAMA_MODELS=$base\ollama-models (applies after Ollama restarts)."
}
if ($restartWsl) { wsl.exe --shutdown *> $null }

# ---- 4. the RAKSHA Linux system, with its disk on the big drive ---------------------------
if ((Wsl-Distros) -notcontains $distro) {
    $tar = "$base\cache\ubuntu-24.04.tar.gz"
    if (-not (Test-Path $tar)) {
        Say "Downloading Ubuntu 24.04 for WSL (~350 MB) to $tar"
        Download $rootfsUrl $tar
    }
    Say "Creating the '$distro' system in $base\wsl"
    wsl.exe --import $distro "$base\wsl" $tar --version 2
    if ($LASTEXITCODE -ne 0) { throw "wsl --import failed (exit $LASTEXITCODE)" }
    Remove-Item $tar -Force
} else {
    Say "Using the existing '$distro' system"
}

# ---- 5. model: an Ollama model can be given up front; any provider is chosen after install ------
if ($Model -match "(-cloud|:cloud)") {
    Write-Host "Note: '$Model' is an Ollama cloud model. Prompts, including the source code being fixed," -ForegroundColor Yellow
    Write-Host "go to ollama.com. Use it on the demo targets or code you may send out. Run 'ollama signin' once." -ForegroundColor Yellow
}

# ---- 6. install everything inside the RAKSHA system --------------------------------------
$sh = "$base\cache\laptop-bootstrap.sh"
$local = Join-Path $PSScriptRoot "laptop-bootstrap.sh"
if ($PSScriptRoot -and (Test-Path $local)) { Copy-Item $local $sh -Force } else { Download "$raw/deploy/laptop-bootstrap.sh" $sh }
$shWsl = "/mnt/" + $d.Name.ToLower() + ($sh.Substring(2) -replace "\\", "/")
$skip = if ($SkipTests) { "1" } else { "0" }
Say "Installing RAKSHA inside '$distro' (10-30 minutes the first time)"
wsl.exe -d $distro -u root -- env "RAKSHA_OLLAMA_MODEL=$Model" "RAKSHA_SKIP_TESTS=$skip" sh -c "tr -d '\r' < '$shWsl' > /tmp/rb.sh && sh /tmp/rb.sh /root/RAKSHA_AI"
if ($LASTEXITCODE -ne 0) { Write-Host "The installer stopped with code $LASTEXITCODE — see above. Re-running this script resumes." -ForegroundColor Red; exit $LASTEXITCODE }

# ---- 6b. choose the model provider (any time later: 'RAKSHA Set Model.bat') ----------------
$enter = "cd /root/RAKSHA_AI && . .venv/bin/activate && . /root/.raksha-env"
$has = (wsl.exe -d $distro -u root -- sh -c "test -f /root/.raksha/provider.json && echo yes") -replace "`0", ""
if (-not $has) {
    Say "Choose the model provider and model (Ollama, LM Studio, vLLM, llama.cpp, OpenAI, DeepSeek, ...)"
    Write-Host "Pick 0 to run model-free for now; change it any time with 'RAKSHA Set Model.bat'."
    wsl.exe -d $distro -u root -- bash -lc "$enter && python -m raksha.provider"
}

# ---- 7. launchers --------------------------------------------------------------------------
Say "Writing launchers to $base"
@"
@echo off
title RAKSHA AI console
echo Starting the RAKSHA console at http://127.0.0.1:8080  (close this window to stop it)
start "" cmd /c "timeout /t 6 >nul & start http://127.0.0.1:8080"
wsl.exe -d $distro -u root -- bash -lc "$enter && python -m raksha.orchestrator"
pause
"@ | Set-Content "$base\RAKSHA Console.bat" -Encoding ASCII
@"
@echo off
title RAKSHA AI shell
wsl.exe -d $distro -u root -- bash -lc "$enter && exec bash -i"
"@ | Set-Content "$base\RAKSHA Shell.bat" -Encoding ASCII
@"
@echo off
title RAKSHA AI model provider
wsl.exe -d $distro -u root -- bash -lc "$enter && python -m raksha.provider && python -m raksha.provider test"
echo The console and every command use this from now on (restart an open console).
pause
"@ | Set-Content "$base\RAKSHA Set Model.bat" -Encoding ASCII
@"
@echo off
title RAKSHA AI checks
wsl.exe -d $distro -u root -- bash -lc "$enter && export RAKSHA_PROVIDER=off && python -m raksha.airgap && python scripts/model_lane_check.py && python -m raksha.slice_autofuzz && python -m pytest -q"
pause
"@ | Set-Content "$base\RAKSHA Checks.bat" -Encoding ASCII
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm $raw/deploy/laptop-bootstrap.ps1)))"
pause
"@ | Set-Content "$base\RAKSHA Update.bat" -Encoding ASCII
@"
@echo off
explorer.exe \\wsl.localhost\$distro\root\RAKSHA_AI
"@ | Set-Content "$base\RAKSHA Files.bat" -Encoding ASCII

try {
    $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath("Desktop")) "RAKSHA Console.lnk"))
    $lnk.TargetPath = "$base\RAKSHA Console.bat"; $lnk.WorkingDirectory = $base; $lnk.Save()
} catch { }

Say "Done"
Write-Host @"
  Everything lives in $base  (the Linux disk is $base\wsl\ext4.vhdx).
  Double-click:
    RAKSHA Console.bat    the web console (opens http://127.0.0.1:8080)
    RAKSHA Shell.bat      a terminal inside the RAKSHA system, ready to run commands
    RAKSHA Checks.bat     air-gap guard, model-lane check, find-fix-prove slice, full tests
    RAKSHA Set Model.bat  choose provider + model (Ollama, LM Studio, vLLM, OpenAI, DeepSeek, ...)
    RAKSHA Files.bat      open the code in Explorer
    RAKSHA Update.bat     pull the latest branch and re-verify
  Guide: docs/laptop-setup.md
"@
