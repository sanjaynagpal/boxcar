# Boxcar — Operator Runbook

This is a runbook for people **running** boxcar day to day — creating and
maintaining vaults, rotating secrets, responding to warnings, recovering
from mistakes. It assumes the binary is already built and named `boxcar`
on your `PATH` (`go build -o boxcar ./cmd/boxcar`).

If you're changing boxcar's code, see `CLAUDE.md` and `DESIGN.md` instead.
For what the tool is contractually supposed to do, see `REQUIREMENTS.md`.

## Quick reference

```
boxcar [-vault NAME] inject <name> <srcFile> [<name> <srcFile> ...]
boxcar [-vault NAME] extract <name> <destPath>
boxcar [-vault NAME] rotate
boxcar [-vault NAME] list
boxcar vaults
boxcar assets
```

`-vault NAME` selects which vault you're operating on. If omitted, it falls
back to `$VAULT_NAME`, then to `dev`. **Get in the habit of always passing
`-vault` explicitly** for anything other than local scratch use — a typo'd
or missing flag silently operates on `dev` instead of erroring, which is
the single easiest operator mistake with this tool.

## Before you start: where vault files live

Every vault is a file, `vault.<NAME>.json`, in **whatever directory you run
`boxcar` from** — there is no fixed system location. Running the same
command from a different directory looks exactly like the vault vanished
(you'll see `(dev vault empty)` or an empty `vaults` listing, not an
error). **Always run boxcar from the same directory for a given vault**, or
script an explicit `cd`. Check `boxcar vaults` first if a vault seems to be
"missing" — it's very likely a `pwd` problem, not data loss.

---

## Procedures

### 1. Create a new vault and store its first secret

```
boxcar -vault prod inject db-password ./db-password.txt
```

- If `vault.prod.json` doesn't exist yet, this **creates it** and prompts
  for a secret twice (`Secret [prod]: ` / `Confirm secret: `) — this secret
  becomes *the* secret for every entry ever added to this vault. If you
  type a secret under `RecommendedSecretLen` (16 chars) or one of a small
  list of very common passwords, you'll see:

  ```
  warning: this secret is short or commonly used; consider a longer, unique passphrase (16+ characters recommended)
  ```

  This is advisory only — it does not stop the injection. **Don't ignore
  it in a real deployment.** The hard-enforced minimum is only 6
  characters (a typo-catcher, not a strength floor).
- On success: `injected 1 file(s) into prod (1 entry total)`.
- The source file (`./db-password.txt` above) is read once and its
  plaintext is never written anywhere except into the encrypted vault file.
  Delete or otherwise secure the original source file yourself — boxcar
  doesn't touch it.

### 2. Add or replace an entry in an existing vault

```
boxcar -vault prod inject api-key ./api-key.txt
```

- You'll be prompted once (`Secret [prod]: `) for the vault's existing
  secret. A wrong secret is rejected with `secret does not match this
  vault` and **nothing is written** — existing entries are untouched.
- Re-using an entry name (`db-password` again, say) **replaces** that
  entry in place; it does not create a duplicate or error.
- Multiple files in one command: `inject a ./a.txt b ./b.txt` — all source
  files are read before anything is written, so a missing/unreadable
  source fails the whole command before the vault is touched.

### 3. Retrieve a secret

```
boxcar -vault prod extract db-password ./restored/db-password.txt
```

- Prompts once for the secret. Parent directories of the destination are
  created as needed. The output file is written `0600`.
- Wrong secret or an unknown entry name both fail cleanly with no output
  file written: `incorrect secret or corrupted entry` / `no entry named
  "..."`.
- **The extracted plaintext file is your responsibility from that point
  on** — boxcar's guarantees stop at the moment the file is written.

### 4. See what's inside a vault (without extracting)

```
boxcar -vault prod list
```

Lists each entry's name and ciphertext size — never plaintext, never even
whether the currently-typed secret is correct (this command doesn't
prompt for a secret at all).

### 5. See all vaults on this host

```
boxcar vaults
```

Lists every `vault.*.json` in the current directory with an entry count.
`(no vaults yet — create one with: boxcar -vault <name> inject ...)` means
exactly that — check you're in the right directory first (see above).

### 6. Rotate a vault's secret (routine)

Do this periodically, and always after procedure #7 below.

```
boxcar -vault prod rotate
```

- Prompts for the **current** secret first (`Current secret [prod]: `) and
  verifies it before asking for anything else — a wrong current secret
  fails immediately with `secret does not match this vault`, and you're
  never asked for a new one.
- Then prompts for a **new** secret, twice, same as procedure #1 (same
  weak-secret warning applies — pick a strong one).
- Every entry is decrypted with the old secret and re-sealed under the new
  one. **This is all-or-nothing**: if anything fails partway through
  (corrupted entry, disk error), the vault file is left completely
  unchanged — you will never end up with a vault half under the old secret
  and half under the new one.
- On success: `rotated secret for prod (N entries)`.
- Rotating an empty vault is refused: `vault "prod" is empty; nothing to
  rotate`.
- Side effect worth knowing: rotation always re-seals under boxcar's
  *current* KDF cost parameters. If you built boxcar against an older
  version whose default scrypt cost was lower, rotating a vault also
  upgrades every entry to the current cost — this is a reasonable reason
  to rotate a long-untouched vault even with no suspected compromise.

### 7. Emergency rotation — suspected secret compromise

If you believe a vault's secret (not just the vault file, the *secret
itself*) may have leaked — it was typed on a compromised machine, shared
over an insecure channel, found in shell history, etc.:

1. **Rotate immediately** (procedure #6), with a freshly chosen, unrelated
   secret — not a variation on the old one.
2. **Understand what rotation does and doesn't fix.** Rotation changes
   what secret unlocks the vault *going forward*. It does **not** undo
   anything an attacker already did with the old secret before you
   rotated: if they already extracted an entry, that plaintext is out
   regardless of any later rotation. Treat every secret protected by the
   old vault secret as compromised from the moment of suspected leak, not
   from the moment you rotated.
3. **Check for secret reuse.** If the same (now-compromised) secret was
   ever reused as another vault's secret, rotate those too — boxcar
   doesn't track or warn about secret reuse across vaults; that's on you.
4. **Re-distribute.** Update every consumer of the vault's contents with
   the newly rotated entries — anyone still holding the old secret has a
   vault file that's now permanently useless to them (correctly).

### 8. Responding to a permission warning

Every command that touches a vault re-checks its file's permissions. If
you see this (on stderr, alongside otherwise-normal output):

```
warning: vault.prod.json is readable by group/other (mode 0644, expected 0600)
```

Something loosened the file after boxcar wrote it `0600` — a manual
`chmod`, a careless `cp`, a restrictive umask override, a sync to a shared
filesystem. Fix it:

```
chmod 600 vault.prod.json
```

This warning is **advisory only** — the command you ran still completed.
It never appears on Windows: `os.FileMode` there doesn't reflect real
ACLs, so the check is intentionally a no-op on that platform (see
`DESIGN.md` if you need the detail). On Windows, rely on NTFS ACLs /
`icacls` instead if this matters for your deployment.

### 9. Back up a vault

`vault.<NAME>.json` is the entire state — back it up like you would any
other file containing encrypted secrets:

- Preserve the `0600` permission bit if your backup tooling supports it.
- **A backup is exactly as brute-forceable as the original** — the
  encryption is what protects it, not where it's stored. Don't treat a
  backup location as inherently safer just because it's "just a backup."
- The backup is useless without the vault's secret, and the secret is
  **never stored anywhere** by boxcar — losing the secret loses the data,
  backup or not (see "Lost secret" below).

### 10. Restore from backup

Copy the backed-up `vault.<NAME>.json` back into the working directory
you run boxcar from, `chmod 600` it if needed, and use `extract` normally.
There's no boxcar-side "restore" command — it's just a file.

---

## Choosing secrets

- Hard minimum: 6 characters. This exists to catch typos, not to certify
  strength — **do not treat it as a target.**
- Recommended: 16+ characters, not a value that appears on common-password
  lists (`vault.IsWeakSecret` checks a small list of the most obvious
  ones — passing that check is a low bar, not a strength guarantee).
- A passphrase (several unrelated words) is easier to type correctly under
  pressure than a short high-entropy string and is generally long enough
  to clear the recommendation comfortably.
- One secret protects **every entry in that vault** — see "Organizing
  vaults" below for how to limit blast radius.

## Organizing vaults across environments

Vaults are cheap and fully isolated (`vault.IsValidName`:
`[A-Za-z0-9_-]`, up to 64 chars) — an entry in one vault is cryptographically
bound to that vault's name and can't be moved or decrypted under another
vault's secret, even by accident. Use this:

- **Partition by sensitivity or blast radius, not just by environment.**
  `-vault prod` holding every production secret behind one shared password
  means compromising that one secret compromises everything in it. Prefer
  several narrower vaults (`prod-db`, `prod-api-keys`, `prod-tls`) over one
  `prod` vault, if the secrets don't all need to be rotated and
  distributed together.
- Set `$VAULT_NAME` in a shell profile or CI job definition rather than
  relying on the `dev` default, so a missing `-vault` flag fails loudly
  (wrong vault, visibly wrong content) instead of silently touching `dev`.
- `boxcar vaults` in a given directory is your ground truth for what
  exists there — run it whenever you're unsure.

---

## Unattended / automated deployments (CI, cron, systemd)

Every procedure above assumes a human is at a terminal to type the vault's
secret. For a pipeline, a cron job, or a service that must `extract` a
secret with nobody watching, boxcar recovers the secret from a pre-wrapped
file plus a locally-held RSA private key instead (`internal/certkey`) —
see `README.md`'s "Full walkthrough" for the canonical worked example this
section summarizes operationally.

`ops/scripts/` and `ops/ansible/` (see `ops/README.md`) automate
procedures #11-15 below for a persistent-host/systemd fleet — the
commands here are still worth reading first, since the tooling is a thin
wrapper around exactly these steps, not a different workflow.

Three files are involved, and they are not equally sensitive:

| File | What it is | On its own |
|---|---|---|
| `vault.<NAME>.json` (e.g. `vault.prod.json`) | The actual encrypted secrets | Useless without `<NAME>`'s secret |
| `<name>.wrapped.json` (any name — it's `cert-wrap`'s output-path arg, not a fixed name) | `<NAME>`'s secret, RSA-encrypted to a public key | Useless without the matching private key |
| `key.pem` (from `cert-gen`, normally kept inside its own `keyvault`) | The RSA private key that unwraps the file above | **The real secret, once it's on disk in plaintext — see procedure #14** |

### 11. One-time provisioning: enable password-free extraction

```
# On your workstation:
boxcar cert-gen ./certs                                    # -> ./certs/cert.pem, ./certs/key.pem
boxcar -vault keyvault inject -dir ./certs                  # prompts for a NEW keyvault password, twice
boxcar -vault prod inject db-password ./db-password.txt     # prompts for prod's password
boxcar -vault prod cert-wrap ./certs/cert.pem ./prod.wrapped.json   # prompts for prod's password AGAIN
```

- `cert-wrap` is not a bystander step — it re-verifies `prod`'s secret
  itself before wrapping it, so expect a **third** password prompt here
  even though `prod` was already unlocked once during `inject`.
- Copy `vault.keyvault.json`, `vault.prod.json`, and `prod.wrapped.json` to
  the target host. None of the three is plaintext on its own.
- **RSA only.** `cert-wrap`/extraction reject any certificate or key that
  isn't RSA (`certificate's public key is *ecdsa.PublicKey, only RSA is
  currently supported`, or similar for the private key) — there's no
  silent fallback for EC material.

### 12. One-time recovery on the target host

```
mkdir ./recovered
boxcar -vault keyvault extract -dir ./recovered      # the one human-typed password on this host
```

- **The recovered key does not land flat.** `inject -dir ./certs` names
  each entry `certs/<file>`, and `extract -dir` reproduces that same
  layout — the key ends up at `./recovered/certs/key.pem`, not
  `./recovered/key.pem`. A script that assumes the flat path will fail
  with "no such file," which has nothing to do with the crypto.
- This step needs a real human at a real terminal (same `terminal.Prompter`
  as every other interactive command) — it is **not** something you can
  run unattended. See procedure #13 for hosts where that's not possible.

### 13. Every subsequent run: fully unattended

```
export VAULT_KEY_FILE=./recovered/certs/key.pem
export VAULT_WRAPPED_SECRET=./prod.wrapped.json
boxcar -vault prod extract db-password ./restored.txt    # no prompt at all
```

- Both variables must be set together, or boxcar exits immediately:
  `error: VAULT_KEY_FILE and VAULT_WRAPPED_SECRET must both be set
  together` (exit code 2) — deliberate fail-fast so a half-configured job
  errors loudly instead of hanging on a prompt with no TTY to write to.
- A wrong/mismatched key and a tampered wrapped file fail identically:
  `incorrect private key or corrupted wrapped secret`. There's no way to
  tell those apart from the error text alone.

### 14. Ephemeral CI runners — procedure #12 doesn't run there

Procedure #12 assumes a persistent host: a human types the keyvault
password once, and the recovered key stays on that disk for every future
run. A GitHub Actions **hosted** runner is a fresh VM every job — there's
no "once" to have, and no human present mid-job to type anything.

For that case, do the recovery in procedure #12 **on your own machine**,
then hand the *already-recovered* `key.pem` to the CI platform's own
secret store (e.g. a repository/environment secret) — never the keyvault
password itself, and never `vault.keyvault.json`. At job start, materialize
that secret to a temp file and point `VAULT_KEY_FILE` at it:

```
- run: echo "$RECOVERED_KEY_PEM" > "$RUNNER_TEMP/key.pem" && chmod 600 "$RUNNER_TEMP/key.pem"
  env:
    RECOVERED_KEY_PEM: ${{ secrets.PROD_RSA_KEY }}
- run: boxcar -vault prod extract db-password ./restored.txt
  env:
    VAULT_KEY_FILE: ${{ runner.temp }}/key.pem
    VAULT_WRAPPED_SECRET: ${{ github.workspace }}/prod.wrapped.json
```

A self-hosted runner or a persistent host (systemd service, a long-lived
cron box) is what procedure #12 actually describes: recover once, leave
`key.pem` on that host's disk, reuse it until the next rotation.

**The recovered private key is the new root of trust on that host.** Once
procedure #12 has run, `key.pem` sits in plaintext at `0600` — the
keyvault password that protected it no longer applies to anything.
`internal/certkey` deliberately does not manage where that key lives
long-term (see `DESIGN.md`'s threat model): anyone who can read that file
on that host can recover `prod`'s secret using `prod.wrapped.json` alone.
Protect it like any other bare secret at rest — restrict it to the service
account that actually runs boxcar, keep it off shared/NFS mounts and out
of backups that aren't equally access-controlled, and prefer a CI-native
secret store, a mounted restricted-permission file, or an HSM over a
hand-copied file when you have the choice.

### 15. Rotating `prod`'s secret breaks `prod.wrapped.json` — re-wrap every time

`boxcar -vault prod rotate` (procedure #6) re-seals every entry under a
**new** secret. `prod.wrapped.json` still only unwraps the **old** one —
`rotate` has no way to know a wrapped file exists and cannot update it.

After every `rotate` on a vault that has any wrapped file in circulation:

```
boxcar -vault prod cert-wrap ./certs/cert.pem ./prod.wrapped.json   # overwrite with the NEW secret, wrapped
```

then redistribute the new `prod.wrapped.json` to every host/pipeline that
uses it. Until you do, unattended `extract` on that vault fails with
`incorrect private key or corrupted wrapped secret` — indistinguishable
from a genuinely corrupted file. **If unattended extraction starts failing
right after a rotation, check whether `prod.wrapped.json` was re-wrapped
and redistributed** before assuming the key was lost or corrupted.

The RSA keypair itself doesn't need to change on rotation — only the
wrapped file. Re-run `cert-gen`/re-provision `keyvault` only if you
suspect the *private key* (not the vault secret) was compromised.

### 16. If a keyvault or data-vault password is forgotten

This workflow (procedures #11-15) runs on **two independent human-chosen
passwords per environment** — the keyvault's and the data vault's (see
`ops/README.md`'s "Multiple environments" table). Boxcar has no backdoor
for either, by design (see "I lost the secret" below) — but *which*
password is gone, and *when* in the lifecycle it's forgotten, changes the
blast radius considerably. It is not always total loss.

**Data-vault password (`prod`, etc.) forgotten:**

- **If `cert-wrap` already ran and `prod.wrapped.json` is distributed:**
  unattended `extract` keeps working *forever* — it only ever goes
  through the RSA envelope (`VAULT_KEY_FILE`/`VAULT_WRAPPED_SECRET`),
  never the human password. What's permanently lost is the ability to
  *write*: `inject` (new entries) and `rotate` both require verifying the
  current secret interactively, and there is no way to do that without
  it. The vault is frozen — readable by every host that already has the
  wrapped file, but it can never gain a new entry or be rotated again.
- **If `cert-wrap` never ran, or the vault predates it:** total loss,
  same as the generic case below — nothing in that vault is recoverable
  by anyone, from any host, ever.

**Keyvault password forgotten:**

- **If procedure #12 (or `prepare-ansible-secret.sh`) already ran on
  every host/control node that needs the RSA key:** mostly harmless day
  to day. The recovered `key.pem` already exists independently of the
  keyvault password (in `ansible-vault`, or wherever it was placed) —
  ongoing unattended `extract` never touches `vault.keyvault.json` again.
  That file becomes a permanently unreadable, orphaned artifact, but
  nothing currently running needs it.
- **If a *new* host or environment needs onboarding later** (i.e.
  procedure #12 has to run again to recover the RSA key onto a machine
  that doesn't have it yet): total loss of that keypair. Every
  `<env>.wrapped.json` ever made with it — across *every* environment
  that shares the keypair — becomes permanently inert. This is exactly
  why "Multiple environments" says to use a **separate** RSA keypair per
  environment: it caps this particular disaster to one environment
  instead of all of them. Recovery is full re-provisioning: new
  `cert-gen`, new keyvault, re-inject the data vault's contents under a
  fresh `cert-wrap`, redistribute to every host again.

**The mitigation is entirely procedural, not a boxcar feature.** Both
passwords need to survive independently of any one operator's memory —
a password manager or an organizational secrets vendor, chosen and
recorded the moment each password is set (during procedure #11's two
`inject`/confirm prompts), plus a documented handoff process for
personnel changes. Nothing in `ops/` automates writing a freshly-chosen
password anywhere on your behalf — that's a deliberate choice, not a gap:
routing a password through any additional store on the way out of a
human's head is one more place it can leak, so this stays a plain
two-password operational discipline rather than new tooling.

---

## Troubleshooting reference

| You see | What it means | What to do |
|---|---|---|
| `invalid vault name "..." (allowed: letters, digits, _ and -, up to 64 chars)` | `-vault`/`$VAULT_NAME` isn't a safe filename component | Fix the name; exit code 2 |
| `secret must be at least 6 characters` | Typed secret is under the hard floor | Re-run, type a longer secret |
| `secrets do not match` | The two secrets typed during a confirm prompt (new vault, or rotate's new secret) didn't match | Re-run, type carefully |
| `secret does not match this vault` | Wrong secret given to `inject` (existing vault) or `rotate`'s current-secret prompt | Confirm you have the right secret for this vault; nothing was written |
| `incorrect secret or corrupted entry` | Wrong secret given to `extract`, or the entry's ciphertext was tampered with/corrupted | Confirm the secret; if you're sure it's right, the vault file itself may be damaged — restore from backup |
| `no entry named "..."` | That name doesn't exist in this vault | Check spelling; `boxcar -vault NAME list` to see what's actually there |
| `vault "NAME" is empty; nothing to rotate` | You ran `rotate` on a vault with zero entries | Nothing to do — there's no secret to rotate yet |
| `read source "...": ...` | `inject`'s source file couldn't be read | Check the path/permissions of the file you're injecting |
| `warning: ... is readable by group/other (mode ...)` | Vault file permissions were loosened after the fact | `chmod 600` it (see procedure #8); this is advisory, the command still ran |
| `error: VAULT_KEY_FILE and VAULT_WRAPPED_SECRET must both be set together` | Only one of the two non-interactive env vars is set | Set both, or neither; exit code 2 |
| `incorrect private key or corrupted wrapped secret` | `certkey.Prompter` couldn't unwrap: wrong private key, tampered wrapped file, or the vault was rotated since the wrapped file was made | Confirm `VAULT_KEY_FILE` matches the cert used in `cert-wrap`; if the vault was rotated since, re-run `cert-wrap` and redistribute (procedure #15) |
| `certificate's public key is *ecdsa.PublicKey, only RSA is currently supported` (or similar) | `cert-wrap`/extraction was pointed at a non-RSA certificate or key | Regenerate with `boxcar cert-gen`, or supply RSA material |
| `vault "NAME" is empty; inject at least one entry before wrapping its secret` | `cert-wrap` run before any `inject` into that vault | Inject at least one entry first |
| `(NAME vault empty)` / `(no vaults yet ...)` | No error — this vault (or directory) genuinely has nothing in it yet | Confirm you're in the expected working directory |
| Exit code 2 | Usage/argument error (bad flags, wrong arg count, invalid vault name) | Check the command syntax against the quick reference |
| Exit code 1 | Command was well-formed but failed (bad secret, missing file, I/O error) | See the specific error message on stderr |

### "I lost the secret"

There is nothing to recover. This is deliberate, not a bug: the secret is
never stored anywhere, and AES-GCM authentication is what proves a secret
is correct — there's no backdoor, no password reset, no admin override.
If the secret for a vault is truly lost, every entry in it is permanently
unrecoverable. Prevent this operationally (a password manager, a secrets
vendor, documented handoff during personnel changes) — not a boxcar
feature request.

---

## What this tool intentionally doesn't do

No audit log, no multi-user access control, no automatic rotation
schedule, no network component, no secret-reuse detection across vaults.
Boxcar is a local, single-operator tool by design. See `DESIGN.md`'s
"Threat model & known limitations" section for the full reasoning behind
each of these before assuming a gap is an oversight.
