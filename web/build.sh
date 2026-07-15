#!/usr/bin/env bash
#
# Copy the AOS 8 -> AOS 10 translation engine into the web assets so the
# browser (Pyodide) runs the *same* code as the CLI. The top-level
# `aos8_acl_converter/` package is the single source of truth; run this whenever
# the engine changes.
#
# The Typer CLI (`cli.py`) and `__main__.py` are intentionally excluded -- the
# web app calls the engine directly and Typer is not available under Pyodide.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/aos8_acl_converter"
DEST="$ROOT/web/public/py/aos8_acl_converter"

MODULES=(
  "__init__.py"
  "canonical.py"
  "enum_tables.py"
  "parser.py"
  "reader.py"
  "renderer.py"
  "report.py"
  "core.py"
  "py.typed"
)

mkdir -p "$DEST"
# Remove stale copies (but keep the directory).
find "$DEST" -maxdepth 1 -type f -delete

for m in "${MODULES[@]}"; do
  cp "$SRC/$m" "$DEST/$m"
done

echo "Copied ${#MODULES[@]} engine files -> web/public/py/aos8_acl_converter/"

# Stage the example configs so the frontend's "Load sample" buttons can fetch
# them from the served assets directory (web/examples/*.cfg).
EX_SRC="$ROOT/examples"
EX_DEST="$ROOT/web/public/examples"
mkdir -p "$EX_DEST"
find "$EX_DEST" -maxdepth 1 -type f -name '*.cfg' -delete
cp "$EX_SRC/sample_aos8.cfg" "$EX_DEST/sample_aos8.cfg"
cp "$EX_SRC/bridge_mode.cfg" "$EX_DEST/bridge_mode.cfg"
echo "Copied 2 example configs   -> web/public/examples/"
