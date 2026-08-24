#!/usr/bin/env bash
# Replaces community.general.expect-based remote bootstrapping with a
# plain ansible-vault-encrypted variable. Run this on your WORKSTATION,
# once per keypair, with a human present.
#
# It runs RUNBOOK.md procedure #12 locally (`boxcar -vault keyvault
# extract -dir`, one interactive password prompt) into a throwaway temp
# directory, then pipes the recovered key.pem straight into
# `ansible-vault encrypt_string` — the plaintext key never touches disk
# outside that temp directory, which is deleted before this script exits.
#
# Usage:
#   prepare-ansible-secret.sh [KEYVAULT_NAME] [OUT_FILE]
#
# Produces OUT_FILE (default: ../ansible/group_vars/boxcar_hosts/vault.yml
# relative to this script), an ansible-vault-encrypted YAML file defining
# `boxcar_recovered_key_pem`. Safe to commit — it's fully encrypted.
#
# You'll be prompted for:
#   1. The keyvault's password (to recover the RSA private key)
#   2. A NEW ansible-vault password to encrypt OUT_FILE with (this is
#      ansible-vault's own password, unrelated to boxcar's — store it in
#      your password manager or an ANSIBLE_VAULT_PASSWORD_FILE, not next
#      to the repo)
#
# Re-run this after re-provisioning the keyvault (new RSA keypair) or if
# OUT_FILE is ever lost. It does NOT need to be re-run after a plain
# `boxcar rotate` on the data vault — that's ops/scripts/rewrap-after-rotation.sh.

set -euo pipefail

BOXCAR_BIN="${BOXCAR_BIN:-boxcar}"
KEYVAULT_NAME="${1:-keyvault}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_file="${2:-$script_dir/../ansible/group_vars/boxcar_hosts/vault.yml}"

command -v "$BOXCAR_BIN" >/dev/null 2>&1 || {
  echo "error: boxcar binary not found (\$BOXCAR_BIN=$BOXCAR_BIN)" >&2
  exit 1
}
command -v ansible-vault >/dev/null 2>&1 || {
  echo "error: ansible-vault not found on PATH" >&2
  exit 1
}

recovered_dir="$(mktemp -d)"
trap 'rm -rf "$recovered_dir"' EXIT

echo "==> [1/2] recovering the private key from $KEYVAULT_NAME (prompts for its password)"
"$BOXCAR_BIN" -vault "$KEYVAULT_NAME" extract -dir "$recovered_dir"

key_path=$(find "$recovered_dir" -name key.pem -print -quit)
if [[ -z "$key_path" ]]; then
  echo "error: no key.pem found under $recovered_dir after extraction" >&2
  exit 1
fi

mkdir -p "$(dirname "$out_file")"

echo
echo "==> [2/2] encrypting it into $out_file (prompts for a NEW ansible-vault password)"
ansible-vault encrypt_string --stdin-name 'boxcar_recovered_key_pem' \
  <"$key_path" >"$out_file"

echo "==> wrote $out_file"
echo "    (the plaintext key only ever existed in $recovered_dir, now deleted)"
echo
echo "Run with: ansible-playbook -i inventory.ini site.yml --ask-vault-pass"
