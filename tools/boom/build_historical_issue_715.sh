#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || "$1" != /* || "$2" != /* ]]; then
  echo "usage: $0 /ABSOLUTE/CHIPYARD /ABSOLUTE/EVIDENCE.json" >&2
  exit 2
fi
chipyard=$1
evidence=$2
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=historical_pins.env
source "$script_directory/historical_pins.env"
# shellcheck source=issue_715_repair_v2.env
source "$script_directory/issue_715_repair_v2.env"
# shellcheck source=issue_715_repair_v3.env
source "$script_directory/issue_715_repair_v3.env"
[[ "$(git -C "$chipyard" rev-parse HEAD)" == "$CHIPYARD_REVISION" ]]
[[ "$(git -C "$chipyard/generators/boom" rev-parse HEAD)" == "$BOOM_REVISION" ]]
lsu="$chipyard/generators/boom/src/main/scala/lsu/lsu.scala"
actual_lsu=$(sha256sum "$lsu" | cut -d' ' -f1)
[[ "$actual_lsu" == "$BOOM_LSU_SHA256" || "$actual_lsu" == "$BOOM_REPAIRED_LSU_SHA256" || "$actual_lsu" == "$BOOM_REPAIR_V2_LSU_SHA256" || "$actual_lsu" == "$BOOM_REPAIR_V3_LSU_SHA256" ]] || {
  echo "historical LSU source is not a reviewed baseline or repair" >&2
  exit 2
}
if [[ "$actual_lsu" == "$BOOM_LSU_SHA256" ]]; then
  variant=historical-issue-715-baseline
elif [[ "$actual_lsu" == "$BOOM_REPAIRED_LSU_SHA256" ]]; then
  variant=historical-issue-715-repaired
elif [[ "$actual_lsu" == "$BOOM_REPAIR_V2_LSU_SHA256" ]]; then
  variant=historical-issue-715-speculative-load-block
else
  variant=historical-issue-715-fault-dependent-kill
fi
miniforge="$(dirname -- "$chipyard")/miniforge3-issue-715"
export PATH="$miniforge/bin:$PATH"
set +u
# shellcheck disable=SC1091
source "$miniforge/etc/profile.d/conda.sh"
# shellcheck disable=SC1091
source "$chipyard/env.sh"
set -u
start=$(date +%s)
make -C "$chipyard/sims/verilator" CONFIG="$BOOM_CONFIG" -j"${SPECHUNTER_BUILD_JOBS:-$(nproc)}"
mapfile -t simulators < <(find "$chipyard/sims/verilator" -maxdepth 1 -type f -executable -name "simulator-*-${BOOM_CONFIG}" -print)
[[ ${#simulators[@]} -eq 1 ]] || { echo "expected exactly one simulator" >&2; exit 2; }
manifest="$chipyard/sims/verilator/spechunter-historical-build.json"
python - "$evidence" "$manifest" "${simulators[0]}" "$start" "$CHIPYARD_REVISION" "$BOOM_REVISION" "$BOOM_CONFIG" "$variant" "$actual_lsu" <<'PY'
import hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
out, manifest, simulator, start, chipyard, boom, config, variant, lsu = sys.argv[1:]
data = {"schema_version": 1, "experiment": "boom-historical-issue-715-build", "variant": variant, "chipyard_revision": chipyard, "boom_revision": boom, "config": config, "lsu_source_sha256": lsu, "simulator_sha256": hashlib.sha256(Path(simulator).read_bytes()).hexdigest(), "elapsed_seconds": int(datetime.now(timezone.utc).timestamp()) - int(start), "completed_at": datetime.now(timezone.utc).isoformat()}
Path(out).write_text(json.dumps(data, indent=2) + "\n")
Path(manifest).write_text(json.dumps(data, indent=2) + "\n")
print(json.dumps(data, indent=2))
PY
