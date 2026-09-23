#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TYPST_BIN=""
if command -v typst >/dev/null 2>&1; then
    TYPST_BIN="typst"
elif [ -x "${ROOT_DIR}/tools/bin/typst" ]; then
    TYPST_BIN="${ROOT_DIR}/tools/bin/typst"
elif [ -x "${HOME}/.local/bin/typst" ]; then
    TYPST_BIN="${HOME}/.local/bin/typst"
else
    echo "Downloading standalone Typst compiler..."
    mkdir -p "${ROOT_DIR}/tools/bin"
    curl -sL "https://github.com/typst/typst/releases/download/v0.15.1/typst-x86_64-unknown-linux-musl.tar.xz" | \
        tar -xJ -C "${ROOT_DIR}/tools/bin" --strip-components=1
    TYPST_BIN="${ROOT_DIR}/tools/bin/typst"
fi

echo "Regenerating vector figures..."
python3 "${SCRIPT_DIR}/generate_figures.py"

echo "Compiling 4-page submission paper to PDF..."
"${TYPST_BIN}" compile "${SCRIPT_DIR}/spechunter.typ" "${SCRIPT_DIR}/spechunter_micro2026.pdf"

echo "Verifying page count..."
PAGE_COUNT=$(python3 -c "
with open('${SCRIPT_DIR}/spechunter_micro2026.pdf', 'rb') as f:
    content = f.read()
import re
print(len(re.findall(rb'/Type\s*/Page\b', content)))
")

if [ "${PAGE_COUNT}" -ne 4 ]; then
    echo "ERROR: Paper must be exactly 4 pages, got ${PAGE_COUNT}"
    exit 1
fi

echo "SUCCESS: ${SCRIPT_DIR}/spechunter_micro2026.pdf is ready (${PAGE_COUNT} pages)."
