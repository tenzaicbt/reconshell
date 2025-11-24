
set -euo pipefail
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
# Print header
bash "$REPO_DIR/scripts/print_header.sh"
# Run the scanner
python3 "$REPO_DIR/reconshell.py" "$@"
