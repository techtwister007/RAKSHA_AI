#!/usr/bin/env sh
# RAKSHA AI — one-command laptop install (Linux, macOS, or Windows via WSL2).
#
#   sh laptop-bootstrap.sh [TARGET_DIR]        default: ~/RAKSHA_AI
#
# Installs everything the system uses on a laptop, clones the repository at the built branch,
# creates the virtualenv, and verifies the install:
#   - toolchains: Python 3.11+, git, gcc (C lane), JDK 17 + Maven (Java), Go 1.22 (Go), cargo
#     (Rust), Node.js (JS) — every lane but the C/Python core is optional and never fails the install
#   - the external scanners RAKSHA can take findings from: semgrep, checkov, gitleaks,
#     osv-scanner (plus its offline database), and opa + cosign for the policy check and the seal
#   - the optional solver (z3) for the bound proofs
#   - ~/.raksha-env: PATH for the tools, and the model settings (Ollama) if RAKSHA_OLLAMA_MODEL is set
# Re-runnable: an existing checkout is updated, tools already present are kept.
#
# Environment knobs (all optional):
#   RAKSHA_OLLAMA_MODEL=<name>   model served by Ollama, e.g. qwen2.5-coder:7b or gpt-oss:120b-cloud
#   RAKSHA_SKIP_TESTS=1          skip the full test suite at the end (the quick checks still run)
#   RAKSHA_MINIMAL=1             core only: no scanners, no extra toolchains
set -eu

TARGET="${1:-$HOME/RAKSHA_AI}"
REPO="https://github.com/techtwister007/RAKSHA_AI.git"
BRANCH="claude/magical-mayer-gs2xno"
TOOLS="$HOME/.raksha-tools"
MINIMAL="${RAKSHA_MINIMAL:-0}"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1; }
SUDO=""; [ "$(id -u)" -ne 0 ] && need sudo && SUDO="sudo"
fetch() { if need curl; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi; }

# ---- 1. toolchains ------------------------------------------------------------------------
say "checking toolchains"
if need apt-get; then
    say "installing packages with apt (you may be asked for your password)"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq python3 python3-venv python3-pip git gcc g++ make libc6-dev \
        curl ca-certificates unzip iproute2 >/dev/null
    if [ "$MINIMAL" != 1 ]; then
        # optional lanes: never fail the install over them
        need mvn   || $SUDO apt-get install -y -qq openjdk-17-jdk-headless maven >/dev/null 2>&1 || true
        need cargo || $SUDO apt-get install -y -qq cargo >/dev/null 2>&1 || true
        need node  || $SUDO apt-get install -y -qq nodejs >/dev/null 2>&1 || true
        need go    || $SUDO apt-get install -y -qq golang-go >/dev/null 2>&1 || true
    fi
else
    for t in python3 git gcc; do need "$t" || { echo "missing $t — install Python 3.11+, git and gcc, then re-run" >&2; exit 1; }; done
fi

# Python 3.11+. An older distro (Ubuntu 22.04 ships 3.10) may carry a newer interpreter as a
# separate package; use it for the venv if so.
PY=python3
pymm() { "$1" -c 'import sys; print("%d%02d" % sys.version_info[:2])' 2>/dev/null || echo 0; }
if [ "$(pymm python3)" -lt 311 ]; then
    for cand in python3.13 python3.12 python3.11; do need "$cand" && { PY="$cand"; break; }; done
    if [ "$(pymm "$PY")" -lt 311 ] && need apt-get; then
        for cand in python3.12 python3.11; do
            if $SUDO apt-get install -y -qq "$cand" "$cand-venv" >/dev/null 2>&1 && need "$cand"; then PY="$cand"; break; fi
        done
    fi
    if [ "$(pymm "$PY")" -lt 311 ]; then
        echo "Python 3.11+ is required and this system only has $(python3 --version 2>&1)." >&2
        echo "On Windows, the installer creates an Ubuntu 24.04 system for you; elsewhere, upgrade Python." >&2
        exit 1
    fi
fi

arch=$(uname -m); case "$arch" in x86_64|amd64) A=amd64;; aarch64|arm64) A=arm64;; *) A="";; esac

# Go 1.21+ for the Go lane (its fix template uses the builtin min). Ubuntu 22.04's Go is 1.18.
gomm() { go version 2>/dev/null | sed -nE 's/.*go1\.([0-9]+).*/\1/p'; }
if [ "$MINIMAL" != 1 ] && [ -n "$A" ] && [ "$(uname -s)" = Linux ]; then
    m=$(gomm); if ! need go || { [ -n "$m" ] && [ "$m" -lt 21 ]; }; then
        say "installing Go 1.22 (official toolchain) for the Go lane"
        if fetch "https://go.dev/dl/go1.22.5.linux-$A.tar.gz" /tmp/go.tgz; then
            $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
            export PATH="/usr/local/go/bin:$PATH"
        else
            echo "  (could not download Go — the Go lane will be skipped; everything else is unaffected)"
        fi
    fi
fi

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
say "creating the virtualenv (runtime has no third-party deps; dev = pytest + jsonschema; z3 optional)"
[ -d .venv ] || "$PY" -m venv .venv
. .venv/bin/activate
pip install -q --upgrade pip >/dev/null 2>&1 || true
pip install -q -e '.[dev]'
[ "$MINIMAL" = 1 ] || pip install -q z3-solver >/dev/null 2>&1 || echo "  (z3 not installed — bound proofs will read 'unavailable')"

# ---- 4. external scanners, policy engine and signer (all optional, all offline at run time) --
mkdir -p "$TOOLS/bin"
export PATH="$TOOLS/bin:$PATH"
if [ "$MINIMAL" != 1 ] && [ -n "$A" ] && [ "$(uname -s)" = Linux ]; then
    say "installing scanners into $TOOLS (semgrep, checkov, gitleaks, osv-scanner, opa, cosign)"
    if [ ! -x "$TOOLS/venv/bin/semgrep" ] || [ ! -x "$TOOLS/venv/bin/checkov" ]; then
        "$PY" -m venv "$TOOLS/venv"
        "$TOOLS/venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
        "$TOOLS/venv/bin/pip" install -q semgrep checkov >/dev/null 2>&1 || echo "  (semgrep/checkov install failed — those two lanes stay off)"
    fi
    for t in semgrep checkov; do [ -x "$TOOLS/venv/bin/$t" ] && ln -sf "$TOOLS/venv/bin/$t" "$TOOLS/bin/$t"; done
    gh="https://github.com"
    x64=$([ "$A" = amd64 ] && echo x64 || echo arm64)
    if ! need gitleaks && fetch "$gh/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_$x64.tar.gz" /tmp/gl.tgz; then
        tar -C "$TOOLS/bin" -xzf /tmp/gl.tgz gitleaks && rm -f /tmp/gl.tgz
    fi
    need osv-scanner || { fetch "$gh/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_$A" "$TOOLS/bin/osv-scanner" && chmod +x "$TOOLS/bin/osv-scanner"; } || true
    need opa         || { fetch "$gh/open-policy-agent/opa/releases/download/v0.70.0/opa_linux_${A}_static" "$TOOLS/bin/opa" && chmod +x "$TOOLS/bin/opa"; } || true
    need cosign      || { fetch "$gh/sigstore/cosign/releases/download/v2.4.1/cosign-linux-$A" "$TOOLS/bin/cosign" && chmod +x "$TOOLS/bin/cosign"; } || true
    # osv-scanner's offline vulnerability database: downloaded once now, used offline afterwards
    if need osv-scanner && [ ! -f "$TOOLS/osv-db.ok" ]; then
        say "downloading the osv-scanner offline database (one time)"
        export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$TOOLS/osv-db"
        if osv-scanner --experimental-download-offline-databases --experimental-offline --recursive \
               --format json demo-targets/mixed-estate >/dev/null 2>&1 \
           || [ -d "$TOOLS/osv-db" ]; then
            touch "$TOOLS/osv-db.ok"
        fi
    fi
fi

# ---- 5. maven cache for the Java demo (needs network once; the gate runs Maven offline) -----
if need mvn && need java && [ ! -f "$TOOLS/maven.ok" ]; then
    say "warming the Maven cache for the Java demo (one time, with network)"
    sh deploy/warm-maven.sh && touch "$TOOLS/maven.ok" || echo "  (Maven warm-up failed — the Java demo will be skipped; everything else is unaffected)"
fi

# ---- 6. ~/.raksha-env: tools on PATH, scanners on, model settings ---------------------------
say "writing ~/.raksha-env"
MODEL="${RAKSHA_OLLAMA_MODEL:-}"
[ -z "$MODEL" ] && [ -f "$HOME/.raksha-model" ] && MODEL=$(cat "$HOME/.raksha-model")
[ -n "$MODEL" ] && printf '%s\n' "$MODEL" > "$HOME/.raksha-model"
cat > "$HOME/.raksha-env" <<'ENV'
# RAKSHA AI environment — written by deploy/laptop-bootstrap.sh. Safe to edit.
export PATH="$HOME/.raksha-tools/bin:/usr/local/go/bin:$PATH"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$HOME/.raksha-tools/osv-db"
[ -f "$HOME/.raksha-tools/osv-db.ok" ] && export RAKSHA_OSV_OFFLINE=1
export RAKSHA_TAKE_ALL=1               # take findings from every installed scanner

# --- model (Ollama) ---------------------------------------------------------------------
# The model name lives in ~/.raksha-model (one line). Change it with:  raksha_model <name>
# Ollama runs on Windows; WSL reaches it at 127.0.0.1 (mirrored networking) or at the Windows
# host address otherwise. The first one that answers is used.
raksha_ollama_url() {
    for h in 127.0.0.1 "$(ip route show default 2>/dev/null | awk '{print $3; exit}')"; do
        [ -n "$h" ] && curl -sf -m 2 "http://$h:11434/api/tags" >/dev/null 2>&1 && { echo "http://$h:11434/v1"; return 0; }
    done
    return 1
}
raksha_model() { printf '%s\n' "$1" > "$HOME/.raksha-model"; . "$HOME/.raksha-env"; echo "model: $1"; }
if [ -s "$HOME/.raksha-model" ]; then
    _m=$(cat "$HOME/.raksha-model")
    if _u=$(raksha_ollama_url); then
        export RAKSHA_INFERENCE_BASE_URL="$_u" RAKSHA_REPAIR_MODEL="$_m" RAKSHA_ADVISOR_MODEL="$_m"
        export RAKSHA_INFERENCE_TIMEOUT=300
        case "$_m" in
            *-cloud|*:cloud|*-cloud:*)
                # Cloud models send the prompt (and the source in it) to ollama.com. Sealed mode
                # refuses them; this turns sealed mode off for this shell. Use on demo or own code only.
                export RAKSHA_SEALED=0 ;;
        esac
    else
        unset RAKSHA_INFERENCE_BASE_URL
        echo "(raksha: Ollama not reachable on 11434 — running model-free; start Ollama and open a new shell)" >&2
    fi
fi
raksha_test() { python -m pytest -q "$@"; }   # tests ignore the model/scanner settings above
ENV
grep -q '.raksha-env' "$HOME/.bashrc" 2>/dev/null || printf '\n[ -f ~/.raksha-env ] && . ~/.raksha-env\n' >> "$HOME/.bashrc"

# ---- 7. verify ------------------------------------------------------------------------------
say "installed tools"
for t in python3 git gcc java mvn go cargo node semgrep checkov gitleaks osv-scanner opa cosign; do
    if need "$t"; then printf '  %-12s ok\n' "$t"; else printf '  %-12s absent (that lane is skipped)\n' "$t"; fi
done
say "air-gap guard"
python -m raksha.airgap
say "model-lane check (the gate accepts correct model fixes and rejects wrong ones; no model needed)"
python scripts/model_lane_check.py
say "find → fix → prove on targets with no hand-written harness"
python -m raksha.slice_autofuzz
if [ "${RAKSHA_SKIP_TESTS:-0}" != 1 ]; then
    say "full test suite (several minutes on a laptop; skip with RAKSHA_SKIP_TESTS=1)"
    python -m pytest -q
fi
. "$HOME/.raksha-env" || true
if [ -n "${RAKSHA_INFERENCE_BASE_URL:-}" ]; then
    say "model reachable: ${RAKSHA_REPAIR_MODEL:-?} at $RAKSHA_INFERENCE_BASE_URL"
fi

say "installed at $TARGET"
cat <<EOF

  Open a new shell (or:  . ~/.raksha-env), then:
      cd "$TARGET" && . .venv/bin/activate
      python -m raksha.orchestrator     # console at http://127.0.0.1:8080
      python -m raksha.slice_three      # C, Python, Java through the one gate
      raksha_model <ollama model name>  # switch model;  raksha_test  runs the tests
  Full guide: docs/laptop-setup.md
EOF
