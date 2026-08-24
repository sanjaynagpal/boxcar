# ops/ — automation for unattended boxcar deployments

Scripts and an Ansible role that implement `RUNBOOK.md`'s "Unattended /
automated deployments" section (procedures #11-15) so an operator doesn't
have to type out each `boxcar` command by hand. Read that section first —
this directory is tooling around it, not a replacement for understanding
what it's doing.

Split by where each piece runs:

```
ops/scripts/    workstation-side: produce the vault files (interactive)
ops/ansible/    host-side: distribute them, no interactive step at all
```

## scripts/ — run on your workstation

- **`provision-workstation.sh <manifest-file> [OUT_DIR]`** — wraps
  procedure #11: `cert-gen`, bundle the cert/key pair into `keyvault`,
  inject every secret listed in `manifest-file` (`entry-name:source-file`
  per line, see `manifest.example`) into the data vault, then `cert-wrap` it. You'll be prompted
  interactively for the keyvault password (once, twice to confirm) and
  the data vault's password (twice: once to set/verify it during inject,
  once more for `cert-wrap`, which re-verifies it independently). Produces
  `vault.keyvault.json`, `vault.prod.json`, and `prod.wrapped.json` in
  `OUT_DIR`. `vault.prod.json` and `prod.wrapped.json` are what
  `ansible/site.yml` expects to find alongside it (via `boxcar_local_dir`,
  default `../..` relative to the playbook); `vault.keyvault.json` is
  consumed next, by the script below — it never goes to `ansible/`.

- **`prepare-ansible-secret.sh [KEYVAULT_NAME] [OUT_FILE]`** — wraps
  procedure #12, but instead of leaving it as a manual per-host SSH step,
  runs it once here (`boxcar -vault keyvault extract -dir` into a
  temp directory, one interactive password prompt) and pipes the
  recovered `key.pem` straight into `ansible-vault encrypt_string`. The
  plaintext key never touches disk outside that temp directory, which is
  deleted (`trap ... EXIT`) before the script returns. Produces
  `ansible/group_vars/boxcar_hosts/vault.yml` by default — fully
  encrypted, safe to commit — defining `boxcar_recovered_key_pem` for
  `site.yml` to consume. You'll be prompted for the keyvault's password
  (to recover the key) and then a *separate*, new ansible-vault password
  (to encrypt the output file) — the two are unrelated; keep the latter
  in a password manager or `ANSIBLE_VAULT_PASSWORD_FILE`, not in the repo.

- **`rewrap-after-rotation.sh <vault-name> <cert.pem> <out-wrapped.json> [ansible-playbook args...]`**
  — wraps procedure #15. Run this **immediately** after any
  `boxcar -vault NAME rotate` — the old wrapped file still only unwraps
  the secret that was just rotated away, and nothing else will remind
  you. Pass `ansible-playbook` arguments (e.g. `-i inventory.ini`) to also
  push the freshly re-wrapped file out to every host in one step. Does
  **not** need `prepare-ansible-secret.sh` re-run — the RSA keypair itself
  is untouched by rotating the data vault's secret.

All three scripts respect `$BOXCAR_BIN` if `boxcar` isn't on `PATH`.

## ansible/ — run against your fleet

- **`site.yml`** — provisions a persistent host: copies
  `vault.<vault-name>.json` and `<vault-name>.wrapped.json` onto the host
  (`0600`, owned by a dedicated `boxcar` system user), installs the
  `boxcar` binary, and writes `key.pem` from the `boxcar_recovered_key_pem`
  variable that `prepare-ansible-secret.sh` produced. There is
  **no interactive step and no pty-allocation trick anywhere in this
  play** — `vault.keyvault.json` and its password never reach these hosts
  or this playbook at all; the one-time recovery (RUNBOOK.md procedure
  #12) already happened, out of band, on a workstation. That's a
  deliberate design choice, not a limitation worked around: boxcar's
  password prompt requires a real controlling terminal
  (`golang.org/x/term.ReadPassword`), which plain SSH-piped stdin can't
  satisfy without something like `expect`/`script` — rather than take on
  that dependency, this design avoids needing it in the first place.

  Idempotent via `ansible.builtin.copy`'s normal content-diff behavior —
  re-running `site.yml` against an already-provisioned fleet just re-syncs
  files and restarts the service only if something actually changed.

  Run with: `ansible-playbook -i inventory.ini site.yml --ask-vault-pass`
  (decrypts `group_vars/boxcar_hosts/vault.yml`; see
  `group_vars/boxcar_hosts/vault.yml.example` for the expected shape).

- **`redistribute-wrapped.yml`** — the fleet-wide half of procedure #15:
  copies a freshly re-wrapped `<vault-name>.wrapped.json` to every host
  and restarts the consuming service. No password or vault needed —
  `cert-wrap` already ran locally when `rewrap-after-rotation.sh` produced
  the file.

- **`roles/boxcar_secrets/`** — the role `site.yml` wraps. See
  `defaults/main.yml` for every variable (host paths, service/user names,
  vault name); override per-host or per-group in your own inventory
  rather than editing the role. `boxcar_recovered_key_pem` deliberately
  has no default — a missing/misconfigured vault file fails loudly via an
  explicit `assert` task rather than writing an empty key.pem.

No extra Ansible collections are required — everything here is
`ansible.builtin` plus `ansible-vault`, which ships with core Ansible.

### What this does and doesn't protect you from

- The raw RSA private key now flows through `ansible-vault` (encrypted at
  rest in `group_vars/boxcar_hosts/vault.yml`, decrypted only in memory
  during a `site.yml` run) rather than through a keyvault password typed
  per host. Every task that handles the decrypted content is
  `no_log: true`, but whoever holds the ansible-vault password for that
  file can recover the key — protect it the way you'd protect any other
  secrets-encryption password. See `RUNBOOK.md` procedure #14's note on
  `key.pem` becoming the new root of trust on each host once it's there,
  which still applies regardless of how it got there.
- Nothing here has been run against a live host as part of writing it —
  treat it as a starting point, dry-run against a single throwaway host
  first (`--limit`), and confirm the systemd restart behavior matches
  your actual service before rolling out further.

## Multiple environments (DEV/TEST/PROD)

Boxcar's per-vault isolation (`RUNBOOK.md`'s "Organizing vaults across
environments") extends naturally here: each environment gets its own
data vault and its own keyvault — two passwords *per* environment, not
two total. With a separate control node per environment (the common
setup), each node only ever handles the one environment it's dedicated
to, so the defaults below work unmodified on each — no environment-aware
naming needed inside the role itself.

| Environment | `VAULT_NAME` | `KEYVAULT_NAME` | Wrapped file |
|---|---|---|---|
| dev  | `dev`  | `keyvault-dev`  | `dev.wrapped.json`  |
| test | `test` | `keyvault-test` | `test.wrapped.json` |
| prod | `prod` | `keyvault-prod` | `prod.wrapped.json` |

**Use a separate RSA keypair per environment too, not just a separate
vault name.** `internal/certkey.go`'s AAD (`aad = []byte("boxcar-cert-
wrapped-secret-v1")`) is a fixed format marker, not bound to a vault or
environment name the way `internal/vault.go`'s per-entry AAD is — so one
RSA keypair reused across environments can unwrap *any* wrapped file ever
made with it, whichever vault's secret is inside. Reuse it for dev and
prod, and a leaked dev-host private key (typically under weaker controls
than prod) also unwraps `prod.wrapped.json`, if an attacker gets a copy
of that file too. `cert-gen`, run once per environment, is what actually
enforces this separation — see the `OUT_DIR` warning below for the one
way to accidentally defeat it.

**Always give `provision-workstation.sh` a distinct `OUT_DIR` per
environment.** Its `cert-gen` step writes to `OUT_DIR/certs`, and it
*skips* regenerating if `cert.pem`/`key.pem` are already there — so
running it for `test` right after `dev` **in the same `OUT_DIR`** silently
reuses dev's keypair for test's `cert-wrap`, exactly the reuse this
section just said to avoid. Distinct output directories sidestep the
whole problem by construction:

```
VAULT_NAME=dev  KEYVAULT_NAME=keyvault-dev  ./provision-workstation.sh manifest-dev.txt  ./out/dev
VAULT_NAME=test KEYVAULT_NAME=keyvault-test ./provision-workstation.sh manifest-test.txt ./out/test
VAULT_NAME=prod KEYVAULT_NAME=keyvault-prod ./provision-workstation.sh manifest-prod.txt ./out/prod
```

Each produces its own `certs/`, `vault.<KEYVAULT_NAME>.json`,
`vault.<VAULT_NAME>.json`, and `<VAULT_NAME>.wrapped.json` under its own
`OUT_DIR` — nothing to name-collide even if you later copy them all
somewhere common.

`prepare-ansible-secret.sh` reads whichever `vault.<KEYVAULT_NAME>.json`
is in the **current directory** (boxcar vault files always live in cwd,
not a configurable path) — `cd` into that environment's `OUT_DIR` first,
and point `OUT_FILE` at that environment's own control node's
`group_vars/` (its default only makes sense when run from inside a
single environment's `ops/ansible/` checkout):

```
cd ./out/dev  && ../../ops/scripts/prepare-ansible-secret.sh keyvault-dev  /path/to/dev-control-node/ops/ansible/group_vars/boxcar_hosts/vault.yml
cd ./out/test && ../../ops/scripts/prepare-ansible-secret.sh keyvault-test /path/to/test-control-node/ops/ansible/group_vars/boxcar_hosts/vault.yml
cd ./out/prod && ../../ops/scripts/prepare-ansible-secret.sh keyvault-prod /path/to/prod-control-node/ops/ansible/group_vars/boxcar_hosts/vault.yml
```

If instead a single shared control node/inventory legitimately manages
more than one environment's hosts (not the "one control node per
environment" case), rename the inventory group and `group_vars/` folder
per environment (`boxcar_hosts_dev`, `boxcar_hosts_test`, ...) and set
`boxcar_vault_name` per group, rather than relying on the single
`boxcar_hosts` default throughout.

Both passwords — keyvault and data vault, per environment — stay
operator-managed (a password manager or secrets vendor, chosen the
moment procedure #11 sets them), same as everywhere else in this
project. See `RUNBOOK.md` procedure #16 for what happens, and what
doesn't, if one is forgotten.
