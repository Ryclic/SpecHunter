#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || "$1" != /* || "$2" != /* ]]; then
  echo "usage: $0 /ABSOLUTE/CHIPYARD_DIRECTORY /ABSOLUTE/EVIDENCE.json" >&2
  exit 2
fi

chipyard_directory=$1
evidence_file=$2
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pins.env
source "$script_directory/pins.env"
[[ "$(git -c safe.directory="$chipyard_directory" -C "$chipyard_directory" rev-parse HEAD)" \
  == "$CHIPYARD_REVISION" ]] || {
  echo "Chipyard revision does not match pins.env" >&2
  exit 2
}

export PATH="$(dirname -- "$chipyard_directory")/miniforge3/bin:$PATH"
set +u
# shellcheck disable=SC1091
source "$chipyard_directory/env.sh"
set -u

start_seconds=$(date +%s)
payload_directory="$(dirname -- "$evidence_file")/spechunter-payloads"
mkdir -p "$payload_directory"
payload="$payload_directory/spechunter-privilege-smoke.riscv"
test_environment="$chipyard_directory/toolchains/riscv-tools/riscv-tests/env"
riscv64-unknown-elf-gcc \
  -march=rv64imafd_zicsr_zifencei -mabi=lp64d -mcmodel=medany \
  -nostdlib -nostartfiles -static \
  -I "$test_environment/p" -I "$test_environment" \
  -T "$test_environment/p/link.ld" "$script_directory/privilege_smoke.S" -o "$payload"

spike_log="${evidence_file%.json}.spike.log"
boom_log="${evidence_file%.json}.boom.log"
spike --isa=rv64imafd_zicsr_zifencei "$payload" >"$spike_log" 2>&1
mapfile -t simulators < <(
  find "$chipyard_directory/sims/verilator" -maxdepth 1 -type f -executable \
    -name "simulator-*-${BOOM_CONFIG}" -print
)
[[ ${#simulators[@]} -eq 1 ]] || {
  echo "expected exactly one $BOOM_CONFIG simulator, found ${#simulators[@]}" >&2
  exit 2
}
simulator=${simulators[0]}
"$simulator" \
  +permissive \
  +dramsim \
  +dramsim_ini_dir="$chipyard_directory/generators/testchipip/src/main/resources/dramsim2_ini" \
  +max-cycles=10000000 \
  +permissive-off \
  "$payload" 2>&1 | tee "$boom_log"
grep -Fq "Verilog \$finish" "$boom_log" || {
  echo "BOOM privilege smoke did not complete" >&2
  exit 1
}

export EVIDENCE_FILE="$evidence_file" BOOM_LOG="$boom_log" SPIKE_LOG="$spike_log"
export PAYLOAD="$payload" SIMULATOR="$simulator" SOURCE="$script_directory/privilege_smoke.S"
export START_SECONDS="$start_seconds" CHIPYARD_REVISION BOOM_CONFIG
export BOOM_REVISION="$(git -c safe.directory="$chipyard_directory/generators/boom" \
  -C "$chipyard_directory/generators/boom" rev-parse HEAD)"
export VERILATOR_VERSION="$(verilator --version)" SPIKE_EXECUTABLE="$(command -v spike)"
python - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def digest(name: str) -> str:
    return hashlib.sha256(Path(os.environ[name]).read_bytes()).hexdigest()


evidence = {
    "schema_version": 1,
    "target": "boom",
    "experiment": "pmp-user-load-denial",
    "chipyard_revision": os.environ["CHIPYARD_REVISION"],
    "boom_revision": os.environ["BOOM_REVISION"],
    "config": os.environ["BOOM_CONFIG"],
    "verilator_version": os.environ["VERILATOR_VERSION"],
    "spike_sha256": digest("SPIKE_EXECUTABLE"),
    "source_sha256": digest("SOURCE"),
    "payload_sha256": digest("PAYLOAD"),
    "simulator_sha256": digest("SIMULATOR"),
    "spike_log_sha256": digest("SPIKE_LOG"),
    "boom_log_sha256": digest("BOOM_LOG"),
    "spike_passed": True,
    "boom_passed": True,
    "elapsed_seconds": int(datetime.now(timezone.utc).timestamp())
    - int(os.environ["START_SECONDS"]),
    "completed_at": datetime.now(timezone.utc).isoformat(),
}
Path(os.environ["EVIDENCE_FILE"]).write_text(json.dumps(evidence, indent=2) + "\n")
PY
cat "$evidence_file"
