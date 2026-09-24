#!/usr/bin/env bash
# Build the submission paper (paper/main.tex) with Tectonic or latexmk.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if command -v tectonic >/dev/null 2>&1; then
    tectonic -X compile main.tex
elif command -v latexmk >/dev/null 2>&1; then
    latexmk -pdf -interaction=nonstopmode main.tex
else
    echo "Install Tectonic (https://tectonic-typesetting.github.io) or TeX Live, or upload" >&2
    echo "main.tex and main.bib to Overleaf (IEEEtran is built in)." >&2
    exit 1
fi
cp main.pdf spechunter_a3_2026.pdf
echo "Wrote paper/spechunter_a3_2026.pdf; the limit is 4 pages."
