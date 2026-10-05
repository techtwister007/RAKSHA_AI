@echo off
rem RAKSHA AI - one-click Windows setup. Double-click this file.
rem Installs everything on D: or E: (whichever has more space) inside a private Linux system (WSL2),
rem then writes double-click launchers into <drive>:\RAKSHA. Safe to run again: it resumes / updates.
rem Optional arguments:  RAKSHA-Setup.bat -Drive E -Model gpt-oss:120b-cloud -SkipTests
title RAKSHA AI setup
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Join-Path '%~dp0' '..\laptop-bootstrap.ps1'; if (-not (Test-Path $p)) { $p = Join-Path $env:TEMP 'raksha-laptop-bootstrap.ps1'; $ProgressPreference = 'SilentlyContinue'; Write-Host 'Downloading the installer...'; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.ps1' -OutFile $p }; & $p %*"
echo.
pause
