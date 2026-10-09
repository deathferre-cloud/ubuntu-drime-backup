#!/usr/bin/env bash
set -euo pipefail
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$project/src${PYTHONPATH:+:$PYTHONPATH}"
export DRIME_RCLONE=${DRIME_RCLONE:-"$project/dist/rclone-fast"}
[ -x "$DRIME_RCLONE" ] || { echo 'Build the client first, or set DRIME_RCLONE.' >&2; exit 1; }
python3 -m unittest discover -s "$project/tests" -p 'test_safety.py' -v
python3 -m unittest discover -s "$project/tests" -p 'test_control.py' -v
python3 -m unittest discover -s "$project/tests" -p 'test_progress.py' -v
python3 -m unittest discover -s "$project/tests" -p 'test_retries.py' -v
python3 "$project/tests/test_local_integration.py"
php -l "$project/src/control.php"
python3 -m compileall -q "$project/src" "$project/scripts"
