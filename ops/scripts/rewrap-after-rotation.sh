#!/usr/bin/env bash
# Wraps RUNBOOK.md procedure #15 ("Rotating prod's secret breaks
# prod.wrapped.json — re-wrap every time"). Run this on your WORKSTATION
# immediately after any `boxcar -vault NAME rotate` — the old wrapped file
# still unwraps to the secret that was just rotated away, and nothing
# reminds you of that automatically.
#
# Usage:
#   rewrap-after-rotation.sh <vault-name> <cert.pem> <out-wrapped.json> [ansible-playbook args...]
#
# If ansible-playbook args are given, ops/ansible/redistribute-wrapped.yml
# is run afterward with them, e.g. to push the new wrapped file straight
# out to every host:
#   rewrap-after-rotation.sh prod ./certs/cert.pem ./prod.wrapped.json -i inventory.ini

set -euo pipefail

BOXCAR_BIN="${BOXCAR_BIN:-boxcar}"

vault_name="${1:?usage: $0 <vault-name> <cert.pem> <out-wrapped.json> [ansible-playbook args...]}"
cert_pem="${2:?missing <cert.pem>}"
out_file="${3:?missing <out-wrapped.json>}"
shift 3

command -v "$BOXCAR_BIN" >/dev/null 2>&1 || {
  echo "error: boxcar binary not found (\$BOXCAR_BIN=$BOXCAR_BIN)" >&2
  exit 1
}
[[ -f "$cert_pem" ]] || {
  echo "error: certificate not found: $cert_pem" >&2
  exit 1
}

echo "==> re-wrapping $vault_name's current secret to $cert_pem"
echo "    (prompts for $vault_name's NEW secret — whatever you just rotated it to)"
"$BOXCAR_BIN" -vault "$vault_name" cert-wrap "$cert_pem" "$out_file"
echo "==> wrote $out_file"

if [[ $# -gt 0 ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  playbook="$script_dir/../ansible/redistribute-wrapped.yml"
  echo "==> redistributing via: ansible-playbook $playbook $*"
  ansible-playbook "$playbook" "$@"
else
  cat <<EOF

Not redistributed automatically. Every host/pipeline still holding the
old $out_file will fail unattended extraction with "incorrect private key
or corrupted wrapped secret" until it gets this new one. Either copy it
out by hand, or re-run with ansible-playbook args appended, e.g.:
  $0 $vault_name $cert_pem $out_file -i ../ansible/inventory.ini
EOF
fi
