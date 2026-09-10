#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 CHIPYARD_DIRECTORY" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
chipyard_directory=$1
[[ "$chipyard_directory" = /* ]] || { echo "CHIPYARD_DIRECTORY must be absolute" >&2; exit 2; }

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pins.env
source "$script_directory/pins.env"

for command in curl git sha256sum gcc g++ make dtc ldd; do
  command -v "$command" >/dev/null || { echo "missing host command: $command" >&2; exit 2; }
done

if [[ -e "$chipyard_directory" ]]; then
  echo "refusing to overwrite existing path: $chipyard_directory" >&2
  exit 2
fi

parent_directory=$(dirname -- "$chipyard_directory")
mkdir -p "$parent_directory"
miniforge_directory="$parent_directory/miniforge3"
installer="$parent_directory/Miniforge3-${MINIFORGE_VERSION}-Linux-x86_64.sh"
installer_url="https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}/Miniforge3-Linux-x86_64.sh"

if [[ ! -x "$miniforge_directory/bin/conda" ]]; then
  curl --fail --location --retry 3 --output "$installer" "$installer_url"
  printf '%s  %s\n' "$MINIFORGE_SHA256" "$installer" | sha256sum --check --status
  bash "$installer" -b -p "$miniforge_directory"
fi

git clone --depth 1 --branch "$CHIPYARD_VERSION" https://github.com/ucb-bar/chipyard.git \
  "$chipyard_directory"
actual_revision=$(git -C "$chipyard_directory" rev-parse HEAD)
[[ "$actual_revision" == "$CHIPYARD_REVISION" ]] || {
  echo "Chipyard revision mismatch: $actual_revision" >&2
  exit 2
}

# Chipyard 1.14's requirement contains an inline explanatory comment. Its setup
# script compares the entire value with ldd and otherwise regenerates every lock
# file. Accept only the reviewed host ABI, then remove that comment so the pinned
# lockfile is consumed as intended.
host_glibc=$(ldd --version | awk '/ldd/{print $NF; exit}')
[[ "$host_glibc" == "$CHIPYARD_GLIBC" ]] || {
  echo "host glibc must be $CHIPYARD_GLIBC (found $host_glibc); use the pinned worker image" >&2
  exit 2
}
glibc_requirement="$chipyard_directory/conda-reqs/chipyard-base.yaml"
grep -Eq "^[[:space:]]*-[[:space:]]*sysroot_linux-64=${CHIPYARD_GLIBC}[[:space:]]*#" \
  "$glibc_requirement" || {
    echo "unexpected Chipyard glibc requirement; refusing to alter it" >&2
    exit 2
  }
sed -Ei "s/^([[:space:]]*-[[:space:]]*sysroot_linux-64=${CHIPYARD_GLIBC})[[:space:]]*#.*/\\1/" \
  "$glibc_requirement"

export PATH="$miniforge_directory/bin:$PATH"
cd "$chipyard_directory"
# Lean mode excludes FireSim, FireMarshal, and their large dependency sets. Precompile
# is deferred until after the pinned BOOM configuration passes environment checks.
./build-setup.sh --use-lean-conda --skip-precompile

source env.sh
printf 'chipyard_revision=%s\n' "$(git rev-parse HEAD)"
printf 'boom_revision=%s\n' "$(git -C generators/boom rev-parse HEAD)"
printf 'verilator_version=%s\n' "$(verilator --version)"
printf 'riscv_gcc=%s\n' "$(riscv64-unknown-elf-gcc --version | head -1)"
