#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || "$1" != /* ]]; then
  echo "usage: $0 /ABSOLUTE/INSTALL_ROOT" >&2
  exit 2
fi
install_root=$1
chipyard="$install_root/chipyard-issue-715"
miniforge="$install_root/miniforge3-issue-715"
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=historical_pins.env
source "$script_directory/historical_pins.env"
[[ ! -e "$chipyard" && ! -e "$miniforge" ]] || { echo "historical install already exists" >&2; exit 2; }

installer=$(mktemp --suffix=.sh)
trap 'rm -f "$installer"' EXIT
curl -fL "https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}/Miniforge3-${MINIFORGE_VERSION}-Linux-x86_64.sh" -o "$installer"
echo "$MINIFORGE_SHA256  $installer" | sha256sum -c -
bash "$installer" -b -p "$miniforge"
"$miniforge/bin/conda" install -y -n base -c conda-forge "conda-lock=$CONDA_LOCK_VERSION"

git clone https://github.com/ucb-bar/chipyard.git "$chipyard"
git -C "$chipyard" checkout --detach "$CHIPYARD_REVISION"
(
  cd "$chipyard"
  PATH="$miniforge/bin:$PATH" ./build-setup.sh --force riscv-tools
)
[[ "$(git -C "$chipyard" rev-parse HEAD)" == "$CHIPYARD_REVISION" ]]
[[ "$(git -C "$chipyard/generators/boom" rev-parse HEAD)" == "$BOOM_REVISION" ]]
echo "$BOOM_LSU_SHA256  $chipyard/generators/boom/src/main/scala/lsu/lsu.scala" | sha256sum -c -
