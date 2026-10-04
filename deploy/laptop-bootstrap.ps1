# RAKSHA AI — one-command Windows install. Paste into PowerShell:
#
#   irm https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.ps1 | iex
#
# Picks the drive with the most free space out of D: and E: (falls back to C:), then runs the
# Linux bootstrap inside WSL2 — the gate needs fork/sh/gcc/ASan, which are POSIX, so on Windows
# the system runs under WSL2 (a real Linux kernel; behaviour is identical to a Linux box).
# The checkout lands at <drive>:\RAKSHA_AI (seen from WSL as /mnt/<drive>/RAKSHA_AI).

$ErrorActionPreference = "Stop"
$branch = "claude/magical-mayer-gs2xno"
$script = "https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/$branch/deploy/laptop-bootstrap.sh"
$installHint = "In an *Administrator* PowerShell run:   wsl --install -d Ubuntu-24.04`n" +
               "then reboot, open 'Ubuntu 24.04' once to create your Linux user, and paste this command again."

# ---- 1. drive with the most free space (D: or E:, else C:) ----
$candidates = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -in @("D", "E") -and $_.Free }
$drive = $candidates | Sort-Object Free -Descending | Select-Object -First 1
if (-not $drive) { $drive = Get-PSDrive C }
$letter = $drive.Name.ToLower()
$target = "/mnt/$letter/RAKSHA_AI"
Write-Host ("Installing to {0}:\RAKSHA_AI  ({1:N1} GB free)" -f $drive.Name, ($drive.Free / 1GB))

# ---- 2. WSL2 with a Linux distro ----
if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Host "WSL is not installed.`n$installHint"; exit 1
}
# `wsl -l -q` emits UTF-16 with embedded NULs when captured; strip them or names come out as "U\0b\0u…".
$distros = @(wsl -l -q 2>$null | ForEach-Object { ($_ -replace "`0", "").Trim() } | Where-Object { $_ })
if ($distros.Count -eq 0) {
    Write-Host "No Linux distro in WSL yet.`n$installHint"; exit 1
}
# Prefer Ubuntu 24.04 (Python 3.12, Go 1.22 from apt). An older Ubuntu (22.04: Python 3.10,
# Go 1.18) still works — the Linux bootstrap installs newer Python/Go itself — but 24.04 is the
# path with the fewest moving parts.
$distro = ($distros | Where-Object { $_ -match "24\.04" } | Select-Object -First 1)
if (-not $distro) { $distro = ($distros | Where-Object { $_ -match "Ubuntu" } | Select-Object -First 1) }
if (-not $distro) { $distro = $distros[0] }
Write-Host "Using WSL distro: $distro"

# ---- 3. hand over to the Linux bootstrap (it installs toolchains, clones, verifies) ----
Write-Host "Running the installer inside WSL (you may be asked for your Linux sudo password) ..."
wsl -d $distro -e sh -c "(command -v curl >/dev/null && curl -fsSL '$script' || wget -qO- '$script') | sh -s -- '$target'"
if ($LASTEXITCODE -ne 0) { Write-Host "Installer exited with code $LASTEXITCODE — see the output above."; exit $LASTEXITCODE }

Write-Host ""
Write-Host ("Done. Open '{0}' and run:  cd {1} && . .venv/bin/activate && python -m raksha.slice_autofuzz" -f $distro, $target)
