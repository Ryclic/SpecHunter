#!/usr/bin/env bash
# Offline reproduction of every checked-in result that does not need a BOOM worker.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[1/4] Lint and format"
uv run ruff check .
uv run ruff format --check .

echo "[2/4] Tests (includes rescans of the four raw issue #715 waveforms)"
uv run pytest -q -m 'not chia'

echo "[3/4] Recompute every evidence seal"
uv run python tools/verify_evidence.py

echo "[4/4] Rebuild the sealed evidence viewer"
uv run spechunter present \
  --input docs/evidence/vertex-boom-demo-2026-09-11.json \
  --seal docs/evidence/vertex-boom-demo-seal-2026-09-11.json \
  --corpus docs/evidence/boom-attack-corpus-2026-09-16.json \
  --corpus-seal docs/evidence/boom-attack-corpus-seal-2026-09-16.json \
  --evaluation docs/evidence/fixture-guided-vs-random-2026-09-19.json \
  --evaluation-seal docs/evidence/fixture-guided-vs-random-seal-2026-09-19.json \
  --repeatability docs/evidence/vertex-fixture-repeatability-2026-09-16.json \
  --repeatability-seal docs/evidence/vertex-fixture-repeatability-seal-2026-09-16.json \
  --chia-evidence docs/evidence/chia-vertex-loop-2026-09-16.json \
  --chia-seal docs/evidence/chia-vertex-loop-seal-2026-09-16.json \
  --rtl-repair-seal docs/evidence/boom-load-gate-regression-seal-2026-09-16.json \
  --issue-715-seal docs/evidence/boom-issue-715-assessment-seal-2026-09-16.json \
  --issue-715-attachment-seal docs/evidence/boom-issue-715-attachment-demo-seal-2026-09-20.json \
  --output artifacts/demo.html
cmp artifacts/demo.html docs/demo.html && echo "docs/demo.html matches a fresh render"
