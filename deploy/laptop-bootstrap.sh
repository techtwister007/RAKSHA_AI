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
for t in python3 git gcc mvn java go; do
    if need "$t"; then printf '  %-8s ok\n' "$t"; else printf '  %-8s absent (optional lane skipped)\n' "$t"; fi
done
pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "$pyver" in 3.1[1-9]|3.[2-9]*) ;; *) echo "Python $pyver found; 3.11+ required" >&2; exit 1;; esac

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
[ -d .venv ] || python3 -m venv .venv
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
