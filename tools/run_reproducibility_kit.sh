#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "  SpecHunter: MICRO 2026 A³ CHIA Hackathon Reproducibility Kit   "
echo "================================================================="

# 1. Environment and Code Quality
echo "[1/4] Checking code quality and running test suite..."
PYTHONPATH=src .venv/bin/ruff check .
PYTHONPATH=src .venv/bin/ruff format --check .
PYTHONPATH=src .venv/bin/pytest -q -m 'not chia'

# 2. Comprehensive Artifact Verification
echo "[2/4] Verifying all cryptographic seals and paper deliverables..."
PYTHONPATH=src .venv/bin/python tools/verify_all_artifacts.py

# 3. Generate Interactive Presentation
echo "[3/4] Generating sealed interactive demonstration viewer..."
PYTHONPATH=src .venv/bin/python -m spechunter.cli present \
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

# 4. Summary
echo "[4/4] Reproducibility verification complete!"
echo "-----------------------------------------------------------------"
echo "Deliverables Ready for Submission:"
echo "  1. 4-Page Paper PDF:      paper/spechunter_micro2026.pdf"
echo "  2. Paper LaTeX Source:    paper/spechunter.tex"
echo "  3. Interactive Demo:      artifacts/demo.html (also at docs/demo.html)"
echo "  4. Composable CHIA Block: spechunter.chia_nodes.SpecHunterSecurityAuditBlock"
echo "  5. Cryptographic Seals:   docs/evidence/*"
echo "================================================================="
