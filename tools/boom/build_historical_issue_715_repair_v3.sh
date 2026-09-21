#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 || "$1" != /* || "$2" != /* || "$3" != /* ]]; then
  echo "usage: $0 /ABSOLUTE/BASELINE /ABSOLUTE/REPAIRED /ABSOLUTE/EVIDENCE.json" >&2
  exit 2
fi
baseline=$1
repaired=$2
evidence=$3
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=historical_pins.env
source "$script_directory/historical_pins.env"
# shellcheck source=issue_715_repair_v3.env
source "$script_directory/issue_715_repair_v3.env"
[[ ! -e "$repaired" ]] || { echo "repaired checkout already exists" >&2; exit 2; }
cp -a --reflink=auto "$baseline" "$repaired"
boom="$repaired/generators/boom"
patch_file="$script_directory/patches/issue_715_historical_kill_fault_dependents.patch"
echo "$BOOM_REPAIR_V3_PATCH_SHA256  $patch_file" | sha256sum -c -
git -C "$boom" apply "$patch_file"
echo "$BOOM_REPAIR_V3_LSU_SHA256  $boom/src/main/scala/lsu/lsu.scala" | sha256sum -c -
rm -rf "$repaired/sims/verilator/generated-src" "$repaired/sims/verilator/output"
find "$repaired/sims/verilator" -maxdepth 1 -type f \
  -name "simulator-*-${BOOM_CONFIG}" -delete
"$script_directory/build_historical_issue_715.sh" "$repaired" "$evidence"
