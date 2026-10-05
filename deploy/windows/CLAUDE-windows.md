# RAKSHA AI on this Windows laptop

This folder holds the launchers and the disk of a private WSL2 Linux system named **RAKSHA**.
The project itself lives inside that system at `/root/RAKSHA_AI` (branch
`claude/magical-mayer-gs2xno`). Read its `HANDOFF.md` and `CLAUDE.md` first:
`\\wsl.localhost\RAKSHA\root\RAKSHA_AI\HANDOFF.md`.

How to work on it from Windows:
- **Run any project command** through WSL, with the project environment loaded:
  `wsl -d RAKSHA -u root -- bash -lc "cd /root/RAKSHA_AI && . .venv/bin/activate && . /root/.raksha-env && <command>"`
- **Read and edit files** at `\\wsl.localhost\RAKSHA\root\RAKSHA_AI\...`. Run git, tests and
  Python inside WSL, never from Windows on that path.
- **Model provider:** `python -m raksha.provider show | test | set ... | off` (run inside WSL).
  Ollama runs on Windows. This Windows build (22000) has no WSL mirrored networking, so WSL
  reaches Ollama at the default gateway. That needs:
  - `OLLAMA_HOST=0.0.0.0:11434` set for the user, then Ollama restarted;
  - a firewall rule for TCP 11434 limited to `172.16.0.0/12`.
- **Launchers here:** `RAKSHA Console.bat` (http://127.0.0.1:8080), `RAKSHA Shell.bat`,
  `RAKSHA Checks.bat`, `RAKSHA Set Model.bat`, `RAKSHA Update.bat`.
- **Status:** `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/techtwister007/RAKSHA_AI/refs/heads/claude/magical-mayer-gs2xno/deploy/laptop-bootstrap.ps1))) -Status`

Rules (from the project's CLAUDE.md):
- The five-check gate decides; models only propose.
- No reproducer, no report.
- Never call a target "secure".
- Every number is measured or null.
- No network calls outside `raksha/inference.py`.
- Never skip or weaken tests.
- Never commit keys.
- Commit and push only to `claude/magical-mayer-gs2xno`.
