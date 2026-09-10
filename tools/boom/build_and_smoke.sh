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

[[ "$(git -C "$chipyard_directory" rev-parse HEAD)" == "$CHIPYARD_REVISION" ]] || {
  echo "Chipyard revision does not match pins.env" >&2
  exit 2
}

export PATH="$(dirname -- "$chipyard_directory")/miniforge3/bin:$PATH"
# shellcheck disable=SC1091
set +u
source "$chipyard_directory/env.sh"
set -u

start_seconds=$(date +%s)
jobs=${SPECHUNTER_BUILD_JOBS:-$(nproc)}
payload_directory="$chipyard_directory/tests/build"
mkdir -p "$payload_directory"
riscv64-unknown-elf-gcc \
  -march=rv64imafd -mabi=lp64d -mcmodel=medany -O2 -Wall -Wextra \
  -fno-common -fno-builtin-printf -static -specs=htif_nano.specs -T htif.ld \
  "$chipyard_directory/tests/hello.c" -o "$payload_directory/hello.riscv"

make -C "$chipyard_directory/sims/verilator" CONFIG="$BOOM_CONFIG" -j"$jobs"
mapfile -t simulators < <(
  find "$chipyard_directory/sims/verilator" -maxdepth 1 -type f -executable \
    -name "simulator-*-${BOOM_CONFIG}" -print
)
[[ ${#simulators[@]} -eq 1 ]] || {
  echo "expected exactly one $BOOM_CONFIG simulator, found ${#simulators[@]}" >&2
  exit 2
}
simulator=${simulators[0]}
hello_binary="$chipyard_directory/tests/build/hello.riscv"
smoke_log="${evidence_file%.json}.smoke.log"

make -C "$chipyard_directory/sims/verilator" CONFIG="$BOOM_CONFIG" \
  BINARY="$hello_binary" BREAK_SIM_PREREQ=1 run-binary-fast 2>&1 | tee "$smoke_log"
grep -Fq "Hello world from core 0, a sonicboom" "$smoke_log" || {
  echo "BOOM smoke output did not contain the expected payload" >&2
  exit 1
}

export EVIDENCE_FILE="$evidence_file" SMOKE_LOG="$smoke_log" SIMULATOR="$simulator"
export HELLO_BINARY="$hello_binary" START_SECONDS="$start_seconds"
export CHIPYARD_REVISION BOOM_CONFIG
export BOOM_REVISION="$(git -C "$chipyard_directory/generators/boom" rev-parse HEAD)"
export VERILATOR_VERSION="$(verilator --version)"
export RISCV_GCC_VERSION="$(riscv64-unknown-elf-gcc --version | head -1)"
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
    "chipyard_revision": os.environ["CHIPYARD_REVISION"],
    "boom_revision": os.environ["BOOM_REVISION"],
    "config": os.environ["BOOM_CONFIG"],
    "verilator_version": os.environ["VERILATOR_VERSION"],
    "riscv_gcc_version": os.environ["RISCV_GCC_VERSION"],
    "simulator_sha256": digest("SIMULATOR"),
    "payload_sha256": digest("HELLO_BINARY"),
    "smoke_log_sha256": digest("SMOKE_LOG"),
    "elapsed_seconds": int(datetime.now(timezone.utc).timestamp())
    - int(os.environ["START_SECONDS"]),
    "completed_at": datetime.now(timezone.utc).isoformat(),
}
Path(os.environ["EVIDENCE_FILE"]).write_text(json.dumps(evidence, indent=2) + "\n")
PY

cat "$evidence_file"
