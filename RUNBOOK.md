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
