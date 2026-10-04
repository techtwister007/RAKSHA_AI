#!/usr/bin/env sh
# RAKSHA AI — one-command laptop install (Linux, macOS, or Windows via WSL2).
#
#   sh laptop-bootstrap.sh [TARGET_DIR]        default: ~/RAKSHA_AI
#
# Installs the toolchains it can (apt, with sudo), clones the repository at the built branch,
# creates a virtualenv, warms the Maven cache for the Java demo, then runs the verification:
# the test suite, the air-gap guard, and the no-harness find→fix→prove slice. Re-runnable: an
# existing checkout is updated, not re-cloned. No AI session is involved — this is plain shell.
set -eu

TARGET="${1:-$HOME/RAKSHA_AI}"
REPO="https://github.com/techtwister007/RAKSHA_AI.git"
BRANCH="claude/magical-mayer-gs2xno"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1; }

# ---- 1. toolchains ------------------------------------------------------------------------
say "checking toolchains"
core_missing=""
for t in python3 git gcc; do need "$t" || core_missing="$core_missing $t"; done
if [ -n "$core_missing" ] || ! python3 -c 'import venv' 2>/dev/null; then
    if need apt-get; then
        say "installing required packages with apt (sudo)"
        sudo apt-get update -qq
        sudo apt-get install -y -qq python3 python3-venv python3-pip git gcc libc6-dev
    else
        echo "missing:$core_missing — install Python 3.11+, git and gcc, then re-run" >&2; exit 1
    fi
fi
if need apt-get; then
    # optional lanes: never fail the install over them
    need mvn  || sudo apt-get install -y -qq openjdk-17-jdk-headless maven >/dev/null 2>&1 || true
    need go   || sudo apt-get install -y -qq golang-go >/dev/null 2>&1 || true
fi

# Python 3.11+. An older distro (Ubuntu 22.04 ships 3.10) may still carry a newer interpreter as
# a separate package; use it for the venv if so, otherwise say exactly what to do.
PY=python3
pymm() { "$1" -c 'import sys; print("%d%02d" % sys.version_info[:2])' 2>/dev/null || echo 0; }
if [ "$(pymm python3)" -lt 311 ]; then
    for cand in python3.13 python3.12 python3.11; do
        if need "$cand"; then PY="$cand"; break; fi
    done
    if [ "$(pymm "$PY")" -lt 311 ] && need apt-get; then
        for cand in python3.12 python3.11; do
            if sudo apt-get install -y -qq "$cand" "$cand-venv" >/dev/null 2>&1 && need "$cand"; then PY="$cand"; break; fi
        done
    fi
    if [ "$(pymm "$PY")" -lt 311 ]; then
        echo "Python 3.11+ is required and this distro only has $(python3 --version 2>&1)." >&2
        echo "Easiest fix on Windows: install a current distro —  wsl --install -d Ubuntu-24.04  — and re-run." >&2
        exit 1
    fi
fi
"$PY" -c 'import venv' 2>/dev/null || { need apt-get && sudo apt-get install -y -qq "${PY}-venv" >/dev/null 2>&1 || true; }

# Go 1.21+ for the Go lane (the repair template uses the builtin min). Ubuntu 22.04's apt Go is
# 1.18: too old. Install the official toolchain to /usr/local/go in that case; the lane is optional,
# so a failure here is reported, never fatal.
gomm() { go version 2>/dev/null | sed -nE 's/.*go1\.([0-9]+).*/\1/p'; }
install_go=0
if need go; then
    m=$(gomm); [ -n "$m" ] && [ "$m" -lt 21 ] && install_go=1      # present but too old
elif need apt-get; then
    install_go=1                                                      # absent and apt had none
fi
if [ "$install_go" = 1 ]; then
    arch=$(uname -m); case "$arch" in x86_64) goarch=amd64;; aarch64|arm64) goarch=arm64;; *) goarch="";; esac
    if [ -n "$goarch" ] && { need curl || need wget; }; then
        say "installing Go 1.22 (official toolchain) for the Go lane"
        url="https://go.dev/dl/go1.22.5.linux-$goarch.tar.gz"
        if { need curl && curl -fsSL "$url" -o /tmp/go.tgz; } || wget -qO /tmp/go.tgz "$url"; then
            sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
            export PATH="/usr/local/go/bin:$PATH"
            grep -q '/usr/local/go/bin' "$HOME/.profile" 2>/dev/null || echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.profile"
        else
            echo "  (could not download Go — the Go lane will be skipped; everything else is unaffected)"
        fi
    fi
fi

for t in git gcc mvn java go; do
    if need "$t"; then printf '  %-8s ok\n' "$t"; else printf '  %-8s absent (optional lane skipped)\n' "$t"; fi
done
printf '  %-8s ok (%s)\n' python "$("$PY" --version 2>&1)"
if need go; then m=$(gomm); if [ -n "$m" ] && [ "$m" -lt 21 ]; then
    echo "  note: $(go version | awk '{print $3}') < 1.21 — the Go lane's fix template will not compile; other lanes unaffected"; fi; fi

# ---- 2. the code ---------------------------------------------------------------------------
if [ -d "$TARGET/.git" ]; then
    say "updating existing checkout at $TARGET"
    git -C "$TARGET" fetch -q origin "$BRANCH"
    git -C "$TARGET" checkout -q "$BRANCH"
    git -C "$TARGET" pull -q --ff-only origin "$BRANCH"
else
    say "cloning into $TARGET"
    mkdir -p "$(dirname "$TARGET")"
    git clone -q --branch "$BRANCH" "$REPO" "$TARGET"
fi
cd "$TARGET"

# ---- 3. python environment -----------------------------------------------------------------
say "creating the virtualenv and installing (runtime has no third-party deps; dev = pytest+jsonschema)"
[ -d .venv ] || "$PY" -m venv .venv
. .venv/bin/activate
pip install -q --upgrade pip >/dev/null 2>&1 || true
pip install -q -e '.[dev]'

# ---- 4. maven cache for the Java demo (needs network once; the gate runs Maven offline) -----
if need mvn && need java; then
    say "warming the Maven cache for the Java demo (one time, with network)"
    sh deploy/warm-maven.sh || echo "  (Maven warm-up failed — the Java demo will be skipped; everything else is unaffected)"
fi

# ---- 5. verify ------------------------------------------------------------------------------
say "running the test suite"
python -m pytest -q
say "air-gap guard"
python -m raksha.airgap
say "find → fix → prove on targets with no hand-written harness"
python -m raksha.slice_autofuzz

say "installed at $TARGET"
cat <<EOF

  To use it:
      cd "$TARGET" && . .venv/bin/activate
      python -m raksha.slice_three      # C, Python, Java through the one gate
      python -m raksha.slice_go         # Go deep lane (if go is installed)
      python -m raksha.orchestrator     # console at http://127.0.0.1:8080
  Full guide: docs/laptop-setup.md
EOF
