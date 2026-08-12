# Boxcar — Requirements

Boxcar is a single-binary Go program that ships static assets embedded at
compile time and provides a runtime, secret-protected store ("vault") into
which a user can inject files and later extract them.

## Background / key constraint

Go's `embed.FS` is **read-only and fixed at compile time** — files cannot be
written into it at runtime. Therefore the compile-time embedded filesystem is
used only for static assets, and every *injected* file is stored in a separate,
mutable sidecar file on disk (`vault.<NAME>.json`). This separation is a
deliberate design requirement, not a limitation to work around.

## Functional requirements

### 1. Embedded assets (compile time, read-only)
- Static files under `assets/` are embedded via `//go:embed assets`.
- The `assets` command lists the embedded files.
- Embedded content is never mutated at runtime.

### 2. Inject files with a secret
- A user can inject one or more files into a vault, protected by a secret.
- The secret is never stored. It is used to derive an encryption key
  (scrypt, `N=32768, r=8, p=1`) with a random per-entry salt; the file is
  encrypted with AES-256-GCM.
- Injecting into a **new/empty** vault sets the vault secret and prompts for it
  twice (confirmation).
- Injecting into an **existing** vault verifies the supplied secret against the
  current entries *before* appending. A wrong secret is rejected up front and
  nothing is written. This guarantees every entry in a vault shares one secret.
- Multiple files can be appended in a single command:
  `inject <name> <src> [<name> <src> ...]`. All sources are read before any
  write, so a missing file fails before the vault is modified.
- Re-using an existing entry name replaces that entry in place.
- A whole folder can be injected at once with `inject -dir <srcFolder>`: every
  regular file under `srcFolder` (walked recursively) is injected, using
  `srcFolder`'s own base name (its "parent") joined with the file's path
  relative to `srcFolder` (slash-separated) as its entry name — e.g.
  injecting `.../alpha` containing `x.txt` produces the entry `alpha/x.txt`.
  Recording the parent this way is what keeps two different folders (or a
  folder and an individually named file) that happen to share a bare file
  name from colliding on entry name, and is what `extract -parent` later
  keys off of. This is otherwise identical to the multi-file form — it's
  implemented in terms of it, so the same
  read-everything-before-writing-anything and secret-verification guarantees
  apply. `srcFolder` must already exist and be a directory; otherwise the
  command fails before prompting for a secret.

### 3. Extract files with the correct secret
- A user can extract an entry by name to any destination path.
- Extraction requires the correct secret. Correctness is enforced
  cryptographically: AES-GCM authentication fails on a wrong secret, so there
  is no stored password to compare.
- Decrypted output is written with mode `0600`; parent directories are created
  as needed.
- Every injected file's original base name (`filepath.Base` of the source
  path at inject time) is recorded on its entry as plaintext metadata
  (`Entry.OrigName`, alongside the already-plaintext entry name). If
  `extract <name> <destPath>` is given a `destPath` that is an *existing
  directory*, the file is written inside it under that original name instead
  of requiring `destPath` to already be the exact target file path — so a
  single file can be extracted back out with its exact original name without
  the caller needing to know or retype it. A `destPath` that is not an
  existing directory is still honored literally, as before. This metadata
  survives `rotate` (which re-seals every entry) and is best-effort for
  entries that predate it (falls back to the entry's own name).
- An entire vault can be extracted at once with `extract -dir <destFolder>`:
  every entry is decrypted into `destFolder`, recreating the entry's name as
  a path relative to `destFolder` (mirroring how `inject -dir` derived that
  name), with the final path component replaced by the entry's original
  source file name when one was recorded — so a top-level entry from a
  plain, aliased inject (e.g. `inject db ./db-password.txt`) extracts as
  `destFolder/db-password.txt`, not `destFolder/db`; a folder-injected
  entry's own name already ends in the real file name, so it's unaffected.
  `destFolder` must already exist and be a directory; otherwise the
  command fails before prompting for a secret. Every entry is decrypted
  before anything is written, so a wrong secret, or an entry name that would
  resolve outside `destFolder`, is rejected before any file lands on disk.
- Just the entries from one previously injected folder can be extracted with
  `extract -parent <name> <destFolder>`: only entries whose name starts with
  `<name>/` (as produced by `inject -dir`) are decrypted, and that prefix is
  stripped when writing into `destFolder` — so `extract -parent alpha
  ./alpha-bak` recreates `alpha`'s own layout under `./alpha-bak`, not
  `./alpha-bak/alpha/...`. It's an error if no entries match `<name>`.
  Unlike `-dir`, `destFolder` does not need to already exist — it (and any
  intermediate directories) is created automatically, since the point is to
  recreate a folder that may not exist yet. As with `-dir`, every matching
  entry is decrypted before anything is written.

### 4. Rotate a vault's secret
- A user can replace a vault's secret with a new one via `rotate`.
- The current secret is verified before a new one is asked for; a wrong
  current secret is rejected up front, same as inject.
- The new secret is set with confirmation (asked twice), same as a new
  vault's first inject.
- Every entry is decrypted with the current secret and re-sealed (fresh
  salt and nonce) under the new one. Rotation is all-or-nothing: if any
  entry fails to rotate, the vault is left completely unmodified — it is
  never left with entries under a mix of old and new secrets.
- Rotating an empty vault is rejected (nothing to rotate).

### 5. Multiple named vaults
- Any vault name matching `[A-Za-z0-9_-]` (max 64 chars) is allowed — e.g.
  `dev`, `test`, `prod`, `team-a`, `ci`, `staging`.
- The vault is selected with `-vault NAME`, falling back to `$VAULT_NAME`.
  Vault selection is entirely optional: if neither is given, and exactly one
  `vault.*.json` exists in the store's directory, that vault is used
  automatically; otherwise (no vaults yet, or more than one — genuinely
  ambiguous) the long-standing default of `dev` is used. This lookup never
  runs for `vaults`/`assets`, which aren't scoped to a specific vault.
- Each vault is an isolated sidecar file `vault.<NAME>.json`. Entries and
  secrets do not cross vaults.
- The `vaults` command lists every `vault.*.json` on disk with entry counts.
- The `list` command lists entries in the selected vault.

## Security requirements
- Secrets are read from the terminal without echo; minimum length 6.
- Key derivation: scrypt with a random 16-byte per-entry salt. Each entry
  records the scrypt cost parameters (`N`, `r`, `p`) it was actually sealed
  with, and is decrypted using its own recorded values. This means the
  package's default cost can be raised in a future release without
  breaking any entry sealed under the old cost — only newly sealed entries
  pick up the new default. An entry only picks up a raised cost once it's
  re-sealed (e.g. via `rotate`); it isn't retroactive.
- Encryption: AES-256-GCM with a random per-entry nonce.
- Each entry's AEAD additional-authenticated-data binds the ciphertext to both
  the vault name and the entry name, so entries cannot be moved between vaults
  or renamed without decryption failing.
- Vault files and extracted files are written `0600`.
- Vault writes are atomic-ish (temp file + rename).
- Every command that touches a vault re-checks its sidecar file's
  permissions and prints an advisory warning (never blocking) if it's
  readable by group or other — catching the case where `0600` was later
  loosened outside the tool. This is a Unix permissions concept and is a
  no-op on Windows.

## CLI summary

```
boxcar [-vault NAME] inject <name> <srcFile> [<name> <srcFile> ...]
boxcar [-vault NAME] inject -dir <srcFolder>
boxcar [-vault NAME] extract <name> <destPath>
boxcar [-vault NAME] extract -dir <destFolder>
boxcar [-vault NAME] extract -parent <name> <destFolder>
boxcar [-vault NAME] rotate
boxcar [-vault NAME] list
boxcar vaults
boxcar assets
```

`-vault` defaults to `$VAULT_NAME`, then `dev`. Each vault → `vault.<NAME>.json`.

## Out of scope / notes
- There is no persistent audit log or multi-user access control — a vault's
  secret is all-or-nothing for every entry it holds. `rotate` replaces a
  vault's secret but does not help against ciphertext already exfiltrated
  under the old secret before rotation.
