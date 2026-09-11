#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 || "$1" != /* || "$2" != /* || "$3" != /* ]]; then
  echo "usage: $0 /ABSOLUTE/BASE_CHIPYARD /ABSOLUTE/REPAIRED_CHIPYARD /ABSOLUTE/EVIDENCE.json" >&2
  exit 2
fi
[[ $EUID -ne 0 ]] || { echo "run as the unprivileged build user" >&2; exit 2; }

base=$1
repaired=$2
evidence=$3
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pins.env
source "$script_directory/pins.env"
[[ ! -e "$repaired" ]] || { echo "repaired destination already exists" >&2; exit 2; }
[[ "$(git -c safe.directory="$base" -C "$base" rev-parse HEAD)" == "$CHIPYARD_REVISION" ]]
[[ "$(git -c safe.directory="$base/generators/boom" \
  -C "$base/generators/boom" rev-parse HEAD)" == "$BOOM_REVISION" ]]
base_lsu="$base/generators/boom/src/main/scala/v3/lsu/lsu.scala"
[[ "$(sha256sum "$base_lsu" | cut -d' ' -f1)" == "$BOOM_LSU_SHA256" ]] || {
  echo "baseline LSU source digest mismatch" >&2
  exit 2
}
[[ -z "$(git -c safe.directory="$base/generators/boom" -C "$base/generators/boom" \
  status --porcelain --untracked-files=all)" ]] || {
  echo "baseline BOOM tree must be pristine" >&2
  exit 2
}

start_seconds=$(date +%s)
mkdir -p "$(dirname -- "$repaired")" "$(dirname -- "$evidence")"
cp -a --reflink=auto "$base" "$repaired"
repair_boom="$repaired/generators/boom"
git -c safe.directory="$repair_boom" -C "$repair_boom" apply \
  "$script_directory/patches/gate_faulting_loads.patch"
repaired_lsu="$repair_boom/src/main/scala/v3/lsu/lsu.scala"
[[ "$(sha256sum "$repaired_lsu" | cut -d' ' -f1)" == "$BOOM_REPAIRED_LSU_SHA256" ]] || {
  echo "repaired LSU source digest mismatch" >&2
  exit 2
}
actual_patch_sha=$(git -c safe.directory="$repair_boom" -C "$repair_boom" \
  diff -- src/main/scala/v3/lsu/lsu.scala | sha256sum | cut -d' ' -f1)
[[ "$actual_patch_sha" == "$BOOM_LOAD_GATE_PATCH_SHA256" ]] || {
  echo "applied repair diff mismatch" >&2
  exit 2
}

export PATH="$(dirname -- "$repaired")/miniforge3/bin:$PATH"
set +u
# shellcheck disable=SC1091
source "$repaired/env.sh"
set -u
make -C "$repaired/sims/verilator" CONFIG="$BOOM_CONFIG" clean
make -C "$repaired/sims/verilator" CONFIG="$BOOM_CONFIG" \
  -j"${SPECHUNTER_BUILD_JOBS:-$(nproc)}"
mapfile -t simulators < <(
  find "$repaired/sims/verilator" -maxdepth 1 -type f -executable \
    -name "simulator-*-${BOOM_CONFIG}" -print
)
[[ ${#simulators[@]} -eq 1 ]] || {
  echo "expected exactly one repaired simulator, found ${#simulators[@]}" >&2
  exit 2
}
simulator=${simulators[0]}
manifest="$repaired/sims/verilator/spechunter-build-gate-faulting-loads.json"
export EVIDENCE="$evidence" MANIFEST="$manifest" SIMULATOR="$simulator" START_SECONDS="$start_seconds"
export CHIPYARD_REVISION BOOM_REVISION BOOM_CONFIG BOOM_REPAIRED_LSU_SHA256
export BOOM_LOAD_GATE_PATCH_SHA256
python - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


data = {
    "schema_version": 1,
    "variant": "gate-faulting-loads",
    "chipyard_revision": os.environ["CHIPYARD_REVISION"],
    "boom_revision": os.environ["BOOM_REVISION"],
    "config": os.environ["BOOM_CONFIG"],
    "lsu_source_sha256": os.environ["BOOM_REPAIRED_LSU_SHA256"],
    "patch_sha256": os.environ["BOOM_LOAD_GATE_PATCH_SHA256"],
    "simulator_sha256": digest(os.environ["SIMULATOR"]),
    "elapsed_seconds": int(datetime.now(timezone.utc).timestamp())
    - int(os.environ["START_SECONDS"]),
    "completed_at": datetime.now(timezone.utc).isoformat(),
}
text = json.dumps(data, indent=2) + "\n"
Path(os.environ["MANIFEST"]).write_text(text)
Path(os.environ["EVIDENCE"]).write_text(text)
PY
cat "$evidence"
