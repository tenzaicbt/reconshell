
set -euo pipefail
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
python3 -B "$REPO_DIR/reconshell.py" "$@"
