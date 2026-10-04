# RAKSHA AI — one-command Windows install. Paste into PowerShell:
#
#   irm https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.ps1 | iex
#
# Picks the drive with the most free space out of D: and E: (falls back to C:), then runs the
# Linux bootstrap inside WSL2 — the gate needs fork/sh/gcc, so the system runs under WSL on
# Windows. The checkout lands at <drive>:\RAKSHA_AI (seen from WSL as /mnt/<drive>/RAKSHA_AI).

$ErrorActionPreference = "Stop"
$branch = "claude/magical-mayer-gs2xno"
$script = "https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/$branch/deploy/laptop-bootstrap.sh"

# ---- 1. drive with the most free space (D: or E:, else C:) ----
$candidates = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -in @("D", "E") -and $_.Free }
$drive = $candidates | Sort-Object Free -Descending | Select-Object -First 1
if (-not $drive) { $drive = Get-PSDrive C }
$letter = $drive.Name.ToLower()
$target = "/mnt/$letter/RAKSHA_AI"
Write-Host ("Installing to {0}:\RAKSHA_AI  ({1:N1} GB free)" -f $drive.Name, ($drive.Free / 1GB))

# ---- 2. WSL2 with a Linux distro ----
if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Host "WSL is not installed. In an *Administrator* PowerShell run:  wsl --install -d Ubuntu"
    Write-Host "then reboot, open Ubuntu once to create your user, and run this command again."
    exit 1
}
$distros = (wsl -l -q 2>$null | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $distros) {
    Write-Host "No Linux distro in WSL yet. In an *Administrator* PowerShell run:  wsl --install -d Ubuntu"
    Write-Host "then reboot, open Ubuntu once to create your user, and run this command again."
    exit 1
}

# ---- 3. hand over to the Linux bootstrap (it installs toolchains, clones, verifies) ----
Write-Host "Running the installer inside WSL (you may be asked for your Linux sudo password) ..."
wsl -e sh -c "curl -fsSL '$script' | sh -s -- '$target'"
if ($LASTEXITCODE -ne 0) { Write-Host "Installer exited with code $LASTEXITCODE — see the output above."; exit $LASTEXITCODE }

Write-Host ""
Write-Host ("Done. Open WSL and run:  cd {0} && . .venv/bin/activate && python -m raksha.slice_autofuzz" -f $target)
