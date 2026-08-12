# Boxcar — Design

This document explains *how* boxcar is put together and *why*. For *what* it
must do, see `REQUIREMENTS.md`.

## Goals of the layout

The original implementation was a single `main.go`. It was correct but had
three problems: crypto/storage logic couldn't be unit-tested without a real
terminal attached to stdin, `go:embed` assets were entangled with the CLI
entrypoint, and everything lived in `package main`, so nothing was reusable
or importable. The current layout fixes this with a standard Go project
shape (`cmd/<binary>` + `internal/<package>`) and a small number of
single-responsibility packages connected through narrow interfaces.

```
cmd/boxcar/main.go   entrypoint: wires concrete implementations, calls os.Exit
internal/vault/       encryption + on-disk vault storage (no I/O prompts, no terminal)
internal/assets/      compile-time embedded static files (go:embed)
internal/terminal/    concrete Prompter: reads a secret from a real terminal
internal/cli/         argument parsing + command dispatch (depends on vault + assets + a Prompter interface)
```

Dependency direction is one-way: `cli` depends on `vault`, `assets`, and the
`Prompter` interface it declares; `terminal` depends on `vault` (for
`CheckSecretLength`); `main` is the only package that knows about *all* of
them, since its job is purely to wire concrete types together and hand off
to `cli.App.Run`. `vault` and `assets` depend on nothing internal — they are
the packages doing the actual work and are safe to import from anywhere,
including future non-CLI entrypoints (a library, a test harness, etc.).

## Why package vault has no terminal dependency

`internal/vault` never reads from stdin and never calls `fmt.Print`. It only
deals in `[]byte` secrets and `Entry`/`Vault` values. This is what makes
`internal/vault/vault_test.go` able to test the actual security properties
(wrong secret rejected, AAD binds vault+entry name, upsert replaces by name,
round-trip through `Store` backed by `t.TempDir()`) without mocking a
terminal or spawning a subprocess.

The `Store` type takes a `Dir` field instead of always resolving paths
relative to the process's current working directory. In production `Dir` is
left empty (meaning cwd, matching the original behavior); in tests each test
gets its own `t.TempDir()`, so tests can run in parallel and never touch the
developer's working directory or leave `vault.*.json` files behind.

## Why prompting is an interface

`internal/cli.Prompter` is a one-method interface:

```go
type Prompter interface {
    Prompt(prompt string, confirm bool) ([]byte, error)
}
```

`internal/terminal.Prompter` is the real implementation (`golang.org/x/term`,
no echo, optional second read to confirm a match). `internal/cli/cli_test.go`
uses a `fakePrompter` that returns a queued list of secrets instead. This is
what lets `TestRun_InjectThenExtract` and `TestRun_InjectWrongSecretRejected`
drive the *entire* CLI dispatch path (`App.Run` → flag parsing → command →
vault read/write) end-to-end in-process, including the exact
"new vault sets the secret / existing vault must match it" branching in
`inject`, without any human at a keyboard.

## Security design (unchanged from the original, now easier to verify)

- **Key derivation**: scrypt (`N=32768, r=8, p=1`) with a random 16-byte
  per-entry salt. A per-entry salt (rather than per-vault) means seal
  operations never reuse a key, even when re-injecting the same entry name
  under the same vault secret. `SealEntry` also *records* the cost
  parameters it used on the `Entry` itself (`ScryptN`/`R`/`P`), and
  `OpenEntry` derives the key using an entry's own recorded params
  (`Entry.scryptParams`), not necessarily the package's current consts. This
  is what lets the consts be raised later without breaking existing
  vaults — see "Threat model" below.
- **Encryption**: AES-256-GCM with a random per-entry nonce. Authentication
  is the *only* mechanism that establishes "correct secret" — there is
  deliberately no separate password hash stored anywhere. `Vault.VerifySecret`
  works by attempting to open the vault's first entry; if that succeeds, the
  supplied secret is the vault's secret.
- **AAD binding**: `aad(env, name) = env + "\x00" + name` is passed as
  AES-GCM additional authenticated data on every seal/open. This is what
  makes `TestOpenEntry_AADBindsVaultName` and
  `TestOpenEntry_AADBindsEntryName` fail-closed: copying an `Entry` into a
  different vault's JSON file, or renaming it in place, breaks decryption
  even with the right secret, because the AAD no longer matches what was
  authenticated at seal time.
- **No plaintext file *content* ever touches disk except the user's
  requested destination**: `extract` decrypts into memory and writes once,
  with `0600` permissions. `inject` reads plaintext sources into memory,
  encrypts, and discards the plaintext; only ciphertext is persisted
  (`vault.<NAME>.json`, also `0600`). This is a guarantee about file
  *content*, not entry metadata — `Entry.Name` (and now `Entry.OrigName`,
  the source file's base name at inject time, recorded so
  `extract <name> <destFolder>` can recreate the exact original file name)
  are both stored as plaintext JSON fields by design, since they're needed
  to list and address entries without decrypting anything.
  `cli.App.inject` sets `OrigName` from `filepath.Base` of the source path;
  `Vault.Rotate` must copy it onto the freshly-sealed `Entry` explicitly
  (`SealEntry` has no source-file context to derive it from), or it would
  silently be lost on every rotation.
- **Bulk extraction also needs `OrigName`, not just the single-entry path**:
  `cli.App.extractDir`/`extractParent` reconstruct a destination path from
  each entry's `Name`, but for a plain, aliased inject (`inject db
  ./db-password.txt`), `Name` ("db") carries no relation to the real file
  name at all — only `OrigName` does. `cli.withOrigLeaf(relName, origName)`
  swaps in `origName` as the final path component while preserving any
  directory prefix, so a folder-injected entry (whose `Name`'s own leaf
  already *is* the real file name, e.g. `"alpha/x.txt"`) is unaffected,
  while a top-level aliased entry extracts under its real name instead of
  its alias. Both `extractDir` and `extractParent` route their
  entry-name-to-path construction through it before calling `safeJoin`.
- **Vault name is a filename component**: `vault.IsValidName` (backed by
  `^[A-Za-z0-9_-]{1,64}$`) is enforced in `cli.parseVaultFlag` before the
  name is ever passed to `Store.PathFor`, so a vault name can't be used for
  path traversal (`../`) or to escape the intended directory.
- **Entry names are not similarly restricted, so folder extraction guards
  separately**: `cli.App.injectDir` derives entry names from a source
  folder's own relative paths (safe by construction), but `Entry.Name` in
  general has no `vault.IsValidName`-style pattern enforced on it — an entry
  written by an older version of the tool, or hand-edited into a
  `vault.*.json`, could contain `../`. `cli.App.extractDir` and
  `cli.App.extractParent` (which both reconstruct a destination path from an
  entry's name) call `cli.safeJoin` to reject any name that would resolve
  outside the destination folder, decrypting every entry before writing any
  of them so the rejection happens before a partial extract lands on disk.
- **Folder entry names are namespaced by their source folder ("parent")**:
  `cli.App.injectDir` names each entry `<srcFolder base>/<relative path>`
  rather than just `<relative path>`. Without the prefix, injecting two
  different folders that both happen to contain a same-named file would
  silently overwrite one via `Vault.Upsert` (which matches on `Entry.Name`
  alone). The prefix also becomes the selector `cli.App.extractParent`
  matches against (`strings.HasPrefix(e.Name, parent+"/")`) — it decrypts
  only the matching entries and strips the prefix back off when writing, so
  the parent folder's own layout is recreated under the destination rather
  than nested under a `<parent>/` subdirectory.
- **Secrets are zeroed after use**: `vault.Zero` overwrites a secret (or a
  derived key) in place once it's no longer needed. `newGCM` (`vault.go`)
  zeroes the scrypt-derived AES key right after `aes.NewCipher` consumes it;
  `terminal.Prompter.Prompt` zeroes every buffer it reads and discards along
  the way (a too-short first read, a mismatched confirmation); and
  `cli.App.inject`/`extract` defer `vault.Zero(secret)` on the secret they
  get back from `Prompter.Prompt`. This is documented as defense-in-depth,
  not a guarantee — Go's runtime can still leave other copies behind (string
  conversions, GC moves) that application code has no handle on to zero.

## Non-interactive secret supply (certificate-wrapped)

`internal/terminal.Prompter` requires a real controlling terminal
(`term.ReadPassword` needs an actual TTY), so it cannot work at all in CI,
cron, or a deploy script — there's no human to type anything. `internal/certkey`
adds a second, structurally-identical `Prompter` (`Prompt(prompt string,
confirm bool) ([]byte, error)`, satisfied without importing `internal/cli`
at all, since Go interfaces are structural) that recovers the secret from
two files instead of a keyboard: a private key, and a secret that was
pre-wrapped to the matching public key.

- **Envelope encryption, not direct RSA encryption.** `certkey.WrapSecret`
  does not encrypt the vault secret with RSA directly — RSA-OAEP has a
  plaintext-size ceiling set by the key's modulus (roughly 190 bytes for a
  2048-bit key with SHA-256 OAEP), which a passphrase could exceed. Instead,
  a fresh random AES-256 "data key" is generated per wrap, the actual
  secret is sealed under it with AES-256-GCM, and only that small,
  fixed-size data key is wrapped with RSA-OAEP under the certificate's
  public key — the same pattern cloud KMS "encrypt with a data key" APIs
  use. This means wrapped-secret length is never limited by the
  certificate's RSA key size. See `TestWrapUnwrapRoundTrip_LongSecret`.
- **RSA only, deliberately, for now.** `parseCertPublicKey`/`parsePrivateKey`
  reject any certificate or key that isn't RSA (`TestWrapSecret_NonRSACertRejected`,
  `TestUnwrapSecret_NonRSAKeyRejected`) rather than silently mishandling an
  EC key. EC support (ECIES-style: ephemeral ECDH + HKDF + AES-GCM) was
  considered and deferred — RSA alone already covers the large majority of
  X.509 certificates in practice, and adding EC means a second wrap/unwrap
  code path to implement and test.
- **`cert-wrap` is a one-time, interactive setup step, not a new secret
  source of its own.** `cli.App.certWrap` calls `a.Prompter.Prompt(...)`
  exactly like `inject`/`extract`/`rotate` do — it doesn't know or care
  whether that's a human at a terminal or (recursively) an already-working
  `certkey.Prompter`. In the common case it's a human, once, providing the
  vault's existing secret; `certWrap` verifies it via `Vault.VerifySecret`
  before wrapping, the same current-secret check `rotate` does, so a wrong
  secret is rejected before anything is written.
- **The wrapped-secret file is sensitive but incomplete on its own.**
  `WrappedSecret.Save` writes `0600`, same as vault files, but recovering
  the vault secret from it requires *also* possessing the matching RSA
  private key — this design deliberately does not manage private key
  storage or distribution itself (a CI secret store, a mounted file with
  restricted permissions, an HSM are all reasonable places for that key to
  actually live; see "Considered future enhancements" below for backends
  that were considered and deferred).
- **`main.go` selects the `Prompter`, `internal/cli` never does.** Consistent
  with `cli` depending only on the `Prompter` interface it declares:
  `cmd/boxcar/main.buildPrompter` reads `$VAULT_KEY_FILE` and
  `$VAULT_WRAPPED_SECRET`; both set together selects `certkey.Prompter`,
  neither set falls back to `terminal.Prompter`, and exactly one set is
  treated as a misconfiguration and exits immediately (`os.Exit(2)`) rather
  than silently falling back to a terminal prompt that would just hang or
  error with no TTY attached.
- **`cert-gen` produces the RSA cert/key pair `cert-wrap` needs, and is
  deliberately just a thin CLI wrapper over `certkey.GenerateSelfSigned`.**
  It's a `noVaultCmd` (alongside `vaults`/`assets`) since it doesn't touch
  any vault, and — unlike `inject -dir`/`extract -dir`, which require their
  folder argument to already exist — it creates `outDir` via `os.MkdirAll`,
  since the point is producing a new location, not operating on an
  existing one. The certificate's validity period is set generously (10
  years, `selfSignedValidity`) purely for tooling hygiene: boxcar never
  actually checks expiry or does any trust-chain validation on it (see
  `parseCertPublicKey`, which only ever extracts the public key), so an
  "expired" cert would still wrap/unwrap correctly regardless.
- **Protecting the private key itself is not a separate feature — it's the
  existing folder-vault mechanism, reused.** `cert-gen`'s output
  (`cert.pem`, `key.pem`) is just two files, so bundling them into their
  own password-protected vault is exactly `inject -dir`/`extract -dir`
  against a vault named for the purpose (e.g. `keyvault`) — no new code
  needed for that half of the story. See `README.md`'s "Full walkthrough"
  and `TestRun_FullNonInteractiveWorkflow`, which exercises the entire
  chain — `cert-gen` → bundle into `keyvault` → populate a data vault →
  `cert-wrap` it → simulate a one-time server-side `extract -dir` recovery
  → fully non-interactive `extract` with zero secrets queued.

## Command dispatch

`cli.App.Run` is a thin switch over `args[0]` after `parseVaultFlag` strips
an optional leading `-vault`/`--vault` flag (falling back to `$VAULT_NAME`).
It returns an `int` exit code rather than calling `os.Exit` directly, which
is what makes it callable from tests. Exit codes follow a simple convention
carried over from the original: `2` for usage/argument errors (including an
invalid vault name), `1` for a command that ran but failed (bad secret,
missing entry, unreadable file), `0` for success.

If neither `-vault` nor `$VAULT_NAME` was given, `parseVaultFlag` returns an
empty name with `explicit=false`, and `Run` (for any command other than
`vaults`/`assets`, which aren't vault-scoped) resolves the actual name via
`App.defaultVaultName`: exactly one `vault.*.json` in `Store.Dir` means use
that vault; zero or more than one means fall back to `"dev"`. This has to
happen in `Run`, not `parseVaultFlag`, because picking a default requires
listing the filesystem (`Store.List`) — `parseVaultFlag` only ever looks at
argv and the environment.

`main.go` is intentionally minimal — it only constructs the real `vault.Store`,
`terminal.Prompter`, wires stdout/stderr, and calls `os.Exit(app.Run(...))`.
Nothing in it can be meaningfully unit-tested (it's I/O wiring), so nothing
in it needs to be.

## Threat model & known limitations

The mechanisms in "Security design" above protect the vault file's
*content*. They don't make every risk disappear — the following are known,
accepted limitations, each with what (if anything) mitigates it today.

- **Offline brute-force of a stolen vault file.** Anyone who obtains
  `vault.<NAME>.json` has everything needed to attempt secret guesses
  indefinitely, at whatever rate the KDF cost allows — there's no server
  side to rate-limit or lock out attempts.
  *Mitigation*: scrypt's cost (`N=32768, r=8, p=1`, `vault.go:34-37`) makes
  each guess deliberately expensive (memory- and CPU-hard), which is the
  standard defense when there's no online gate to rely on. In addition,
  `vault.IsWeakSecret` (short of `RecommendedSecretLen`=16, or a match
  against a small list of commonly leaked passwords) drives an advisory
  warning printed by `terminal.Prompter.Prompt` whenever a *new* secret is
  being chosen (`confirm==true` — i.e. setting up a fresh vault).
  *Residual risk*: `MinSecretLen` (the hard-enforced floor, `vault.go:42`) is
  still only 6 characters — a typo-catcher, not a strength guarantee — and
  the weak-secret warning is advisory only, never blocking. A short or
  common secret is still accepted if the user ignores the warning; brute-
  forcing it is a matter of KDF cost, not tool-side prevention. **Operators
  should use a long, high-entropy passphrase, not the 6-character
  minimum.**

- **KDF cost needs to rise as hardware gets faster, without breaking vaults
  sealed under the old cost.** `scryptN`/`R`/`P` are consts, not something
  an operator can tune per vault — and naively bumping them would make
  every *existing* entry silently expect a cost the const no longer
  reflects, since `OpenEntry` would derive the wrong key for old ciphertext.
  *Mitigation*: `SealEntry` records the cost parameters actually used on
  the `Entry` itself (`ScryptN`/`R`/`P`); `OpenEntry` derives the key from
  an entry's *own* recorded params (`Entry.scryptParams`), falling back to
  the package's current consts only for entries that predate this field
  (unmarshaled as zero from an older `vault.*.json`). Raising the consts in
  a future release therefore only affects entries sealed *after* the
  change — every existing entry keeps opening under the cost it was
  actually sealed with. `Vault.Rotate` re-seals every entry under the
  current consts as a side effect, so rotating a vault is also how an
  operator upgrades its entries to a newer cost. See
  `TestOpenEntry_UsesEntrysOwnScryptParams`,
  `TestOpenEntry_LegacyEntryWithoutScryptParams`, and
  `TestStore_Load_LegacyVaultJSONWithoutScryptParams`.
  *Residual risk*: an entry that's never rotated keeps whatever cost it was
  originally sealed under, indefinitely — raising the consts doesn't
  retroactively protect vaults an operator never re-touches.

- **One secret protects the whole vault.** All entries in a vault share one
  secret (`Vault.VerifySecret`, `vault.go:94-105`); compromising that secret
  exposes every entry the vault holds, not just one.
  *Mitigation*: vaults are cheap and isolated by name (`-vault NAME` /
  `$VAULT_NAME`, `internal/cli/cli.go`) — **partition unrelated or
  differently-sensitive content into separate vaults** so a compromised
  secret only exposes that vault's blast radius, not everything.
  *Residual risk*: there is no sub-vault or per-entry secret; this
  partitioning is a usage convention, not something the tool enforces.

- **Key rotation if a secret is suspected compromised.**
  *Mitigation*: `boxcar [-vault NAME] rotate` (`internal/cli.App.rotate` →
  `Vault.Rotate`, `vault.go`). It verifies the current secret before it even
  asks for a new one, then decrypts and re-seals every entry — with fresh
  salts and nonces, same as any `SealEntry` call — under the new secret.
  Rotation is all-or-nothing: entries are rebuilt into a separate slice, and
  `v.Entries` is only reassigned once every single entry has been
  successfully re-sealed, so a failure partway through (a corrupted entry,
  an I/O error) leaves the vault exactly as it was, never with entries split
  across old and new secrets. See `TestVault_Rotate_RoundTrip` and
  `TestVault_Rotate_WrongOldSecretLeavesVaultUnmodified`.
  *Residual risk*: rotation only helps if you rotate *before* an attacker
  who has a copy of the old vault file finishes brute-forcing the old
  secret — once decrypted, old-secret ciphertext copied elsewhere is
  unaffected by a later rotation. There is also no automatic trigger for
  rotation (no expiry, no forced schedule) — it's still something an
  operator has to decide to run.

- **No audit log.** Boxcar records no history of who ran `inject`/`extract`,
  when, or from where — a copy of the vault file being read or exfiltrated
  is undetectable by the tool itself.
  *Mitigation*: none in-tool; this is explicitly out of scope
  (`REQUIREMENTS.md`, "Out of scope / notes"). Rely on OS/filesystem-level
  access auditing if this matters for your use case.

- **`0600` permissions are defense-in-depth, not a security boundary.**
  `Store.Save` (`vault.go:188-199`) and extracted output are written owner-
  only, but that only matters if the OS user account itself is trusted. A
  compromised user account, an unencrypted disk that's later read
  offline, or a backup of the vault file taken without the same care all
  bypass this.
  *Mitigation*: the encryption (not the file mode) is the actual protection
  for content confidentiality — `0600` only reduces accidental exposure
  (e.g. other local users), and isn't something to depend on against a
  motivated attacker with disk access. What boxcar *does* do: it re-checks,
  it doesn't just set-and-forget. `vault.CheckFilePermissions` (called via
  `Store.CheckPermissions`) stats the vault file on every `inject`,
  `extract`, `rotate`, `list`, and `vaults`, and prints a warning to stderr
  if group/other read bits are set — catching the case where a `0600` file
  was later widened by a manual `chmod`, a careless `cp`, an umask, or a
  sync to a shared filesystem. It's advisory only (never blocks a command)
  and is a **Unix permissions concept**: Go's `os.FileMode` on Windows
  doesn't reflect real ACLs (it's synthesized from the read-only attribute
  alone), so the check is intentionally a no-op there — see
  `TestCheckFilePermissions`, which asserts exactly that on Windows.
  **Back up vault files with the same care as any other encrypted
  secret**, since a backup copy is just as brute-forceable as the original,
  and this check only covers the *original* file's permissions, not any
  copy made of it.

- **No multi-user access control.** Whoever can run the `boxcar` binary
  against a vault file and knows (or guesses) the secret can extract
  anything in it — there's no separate authorization layer beyond "knows
  the secret." Out of scope per `REQUIREMENTS.md`; boxcar is a
  single-user, local tool by design, not a shared secrets service.

## Considered future enhancements

Recorded here so the reasoning isn't re-derived from scratch if this comes
up again. Prompted by: "are there any secure passwordless options" for
unlocking a vault, instead of a typed secret — and, in a later session,
specifically "what other options instead of password" for *non-interactive*
use, which led to implementing the certificate-wrapped option below.

- **Certificate-wrapped secret — implemented**, see "Non-interactive secret
  supply (certificate-wrapped)" above (`internal/certkey`, `cert-wrap`).
  This is the "random keyfile" idea below, generalized: rather than a raw
  keyfile *being* the secret (something you have, full stop), the private
  key only *unwraps* a secret that was deliberately encrypted to it — so
  losing or copying the wrapped-secret file alone (without the private key)
  doesn't expose anything, unlike a bare keyfile. It doesn't remove the
  human from the picture entirely: `cert-wrap` still needs a human to
  provide the vault's existing secret once, interactively — what it
  removes is the *ongoing* need for a human on every subsequent
  `extract`/`inject`/`rotate` in CI/cron/deploy contexts.
- **OS keychain integration** (macOS Keychain / Windows Credential Manager
  / Linux Secret Service, e.g. via `github.com/zalando/go-keyring`). Boxcar
  would store the vault secret there instead of prompting for it; unlocking
  becomes whatever already guards the user's OS session (login, biometric).
  Best fit for boxcar's current shape (single binary, offline,
  cross-platform, one small pure-Go-friendly dependency, no hardware
  requirement). The real cost isn't code — it's a trust shift worth being
  explicit about: the vault's protection becomes the OS session's
  protection, not boxcar's own scrypt/AES-GCM design. This is the
  recommended starting point if this is picked up.
- **Hardware security key (FIDO2 `hmac-secret` extension)** — same
  mechanism `age-plugin-yubikey`/`rage` use: a stable secret derived from
  physical possession of the key via challenge-response, no memorized
  value at all. Genuinely hardware-bound and stronger than a keychain, but
  a harder dependency (USB/NFC hardware, a FIDO2 Go library) that this CLI
  doesn't have today, and it changes recovery (losing the key vs.
  forgetting a secret has different failure modes).
- **Random keyfile instead of a typed secret.** Simplest to implement
  (skip the terminal prompt, read a file's bytes as the secret), but it's
  not really "passwordless" in spirit — it's "something you have" instead
  of "something you know," and keyfiles are notoriously easy to lose or
  copy carelessly (defeating the point) without more supporting tooling
  than boxcar currently has (no keyfile generation/backup guidance exists).

None of the still-unimplemented options above are drop-in: each would need
a `Prompter`-equivalent abstraction for a non-terminal secret source — which
is exactly the seam `certkey.Prompter` demonstrates, since `cli.Prompter`
already models "get a secret" abstractly enough to extend rather than
replace — and a decision on how it interacts with the existing scrypt/
AES-GCM per-entry design. None of these options, implemented or not, touch
that design; they only replace *how the secret is obtained*, not how it
protects an entry once obtained.

## Non-goals

Carried over from `REQUIREMENTS.md`: no audit log, no multi-user access
control, no network component. Boxcar is a local, single-binary tool;
every vault's secret is all-or-nothing for every entry it holds, by
design. `rotate` replaces a vault's secret but does not undo exposure of
ciphertext already exfiltrated under the old one.
