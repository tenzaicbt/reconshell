
set -euo pipefail
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
bash "$REPO_DIR/scripts/print_header.sh"
python3 "$REPO_DIR/reconshell.py" "$@"
