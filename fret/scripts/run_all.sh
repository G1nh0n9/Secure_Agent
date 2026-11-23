#!/bin/sh
# Run every stage (or the named ones) and keep the result of each in
# runs/<run id>/.  Usage: scripts/run_all.sh [STAGE ...]
# PYTHON selects the interpreter (3.10 or newer).
set -eu
cd "$(dirname "$0")/.."

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    for candidate in "$HOME/.pyenv/versions/3.12.14/bin/python3" \
        python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))'
        then
            PY="$candidate"
            break
        fi
    done
fi
[ -n "$PY" ] || { echo "Python 3.10 or newer not found" >&2; exit 2; }
docker image inspect fret-lab:latest >/dev/null 2>&1 ||
    { echo "docker image fret-lab:latest not available" >&2; exit 2; }

export PYTHONDONTWRITEBYTECODE=1
exec nice -n 10 "$PY" -m secure_agent_attach full "$@"
