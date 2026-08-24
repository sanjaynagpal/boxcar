#!/usr/bin/env bash
# Wraps RUNBOOK.md procedure #11 ("One-time provisioning: enable
# password-free extraction"). Run this on your WORKSTATION, never on the
# target host — it's the step where plaintext RSA key material briefly
# exists on local disk before being bundled into its own vault.
#
# Produces, in OUT_DIR (default: current directory):
#   certs/cert.pem, certs/key.pem     (from `boxcar cert-gen`)
#   vault.$KEYVAULT_NAME.json          (the cert/key pair, password-protected)
#   vault.$VAULT_NAME.json             (your application secrets)
#   $VAULT_NAME.wrapped.json           (VAULT_NAME's secret, wrapped to cert.pem)
#
# These four artifacts (minus the plaintext certs/ dir) are exactly what
# ops/ansible/site.yml expects to find next to it — see ops/README.md.
#
# Usage:
#   provision-workstation.sh <manifest-file> [OUT_DIR]
#
# manifest-file: lines of "entry-name:source-file", one per secret to
# inject into the data vault, blank lines and #-comments ignored, e.g.:
#   db-password:./secrets/db-password.txt
#   api-key:./secrets/api-key.txt
#
# Env overrides: BOXCAR_BIN (default: boxcar), VAULT_NAME (default: prod),
# KEYVAULT_NAME (default: keyvault).

set -euo pipefail

BOXCAR_BIN="${BOXCAR_BIN:-boxcar}"
VAULT_NAME="${VAULT_NAME:-prod}"
KEYVAULT_NAME="${KEYVAULT_NAME:-keyvault}"

manifest="${1:?usage: $0 <manifest-file> [OUT_DIR]}"
out_dir="${2:-.}"

if [[ ! -f "$manifest" ]]; then
  echo "error: manifest file not found: $manifest" >&2
  exit 1
fi

command -v "$BOXCAR_BIN" >/dev/null 2>&1 || {
  echo "error: boxcar binary not found (\$BOXCAR_BIN=$BOXCAR_BIN)" >&2
  exit 1
}

mkdir -p "$out_dir"
cd "$out_dir"

certs_dir="./certs"

echo "==> [1/4] cert-gen"
if [[ -f "$certs_dir/cert.pem" && -f "$certs_dir/key.pem" ]]; then
  echo "    $certs_dir already has cert.pem/key.pem — skipping (delete it first to regenerate)"
else
  "$BOXCAR_BIN" cert-gen "$certs_dir"
fi

echo
echo "==> [2/4] bundle the cert/key pair into its own vault: $KEYVAULT_NAME"
echo "    (prompts for a NEW password if vault.$KEYVAULT_NAME.json doesn't exist yet,"
echo "     otherwise the EXISTING one)"
"$BOXCAR_BIN" -vault "$KEYVAULT_NAME" inject -dir "$certs_dir"

echo
echo "==> [3/4] inject application secrets into: $VAULT_NAME"
while IFS=':' read -r name src; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  echo "    injecting '$name' from $src"
  "$BOXCAR_BIN" -vault "$VAULT_NAME" inject "$name" "$src"
done <"$manifest"

echo
echo "==> [4/4] wrap $VAULT_NAME's secret to the certificate's public key"
echo "    (prompts for $VAULT_NAME's password AGAIN — cert-wrap re-verifies it)"
"$BOXCAR_BIN" -vault "$VAULT_NAME" cert-wrap "$certs_dir/cert.pem" "$VAULT_NAME.wrapped.json"

cat <<EOF

Done. Files ready for distribution (see RUNBOOK.md procedure #12, or
ops/ansible/site.yml to automate it):
  vault.$KEYVAULT_NAME.json
  vault.$VAULT_NAME.json
  $VAULT_NAME.wrapped.json

$certs_dir/ still holds the plaintext RSA key pair — it's only needed
here, on this workstation, now that it's bundled into vault.$KEYVAULT_NAME.json.
Delete it once you've confirmed that vault opens correctly, or keep it
somewhere at least as protected as the vault it came from.
EOF
