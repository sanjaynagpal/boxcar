# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Boxcar (module `github.com/sanjaynagpal/boxcar`) is a Go CLI that demonstrates two coexisting storage models in one binary:

- **Compile-time embedded assets** (`internal/assets`, via `//go:embed assets`) — read-only, fixed at build time.
- **Runtime-mutable, secret-protected vaults** (`vault.<NAME>.json` sidecar files, via `internal/vault`) — where a user injects files (encrypted) and later extracts them with the correct secret.

The core design constraint driving the architecture: Go's `embed.FS` cannot be written to at runtime, so injected files must live in a separate mutable store next to the binary. `REQUIREMENTS.md` is the functional/security spec (source of truth for *what* it must do); `DESIGN.md` explains *how* the package layout and interfaces are put together and why — read both before changing behavior.

## Commands

```
go build ./...              # build everything
go build ./cmd/boxcar        # build just the binary
go vet ./...                 # static checks — run before considering work done
go test ./...                 # run all tests
go test ./internal/vault/... -run TestName -v   # run a single test
go mod tidy                  # sync go.mod/go.sum after dependency changes
go run ./cmd/boxcar <args>    # run without building, e.g. `go run ./cmd/boxcar assets`
```

CLI itself (once built):
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
`-vault` defaults to `$VAULT_NAME`; if neither is given and exactly one `vault.*.json` exists on disk, that vault is used, else `dev`. Each vault is an isolated `vault.<NAME>.json`.

## Architecture

```
cmd/boxcar/main.go     entrypoint — wires concrete implementations, calls os.Exit
internal/vault/         encryption + on-disk vault storage; no terminal/I/O dependency
internal/assets/        compile-time embedded static files (go:embed)
internal/terminal/      concrete Prompter — reads a secret from a real terminal
internal/cli/           argument parsing + command dispatch (App.Run)
```

`internal/vault` and `internal/assets` depend on nothing internal and do no prompting/printing, which is what makes them directly unit-testable (see `internal/vault/vault_test.go`, `internal/assets/assets_test.go`). `internal/cli` depends on both plus a `Prompter` interface it declares itself; `internal/cli/cli_test.go` drives the full command-dispatch path with a fake `Prompter` and a `t.TempDir()`-backed `vault.Store`, so CLI behavior is tested without a real terminal. `internal/terminal.Prompter` is the only piece that touches an actual TTY (`golang.org/x/term`), and `cmd/boxcar/main.go` is the only place that wires everything together — it should stay too thin to need tests.

Key invariants to preserve when modifying vault logic (all in `internal/vault/vault.go` unless noted):

- **One secret per vault.** All entries in a given `vault.<NAME>.json` are encrypted under the same secret. Injecting into a non-empty vault must verify the supplied secret against an existing entry (`Vault.VerifySecret`, checked against `Entries[0]`) *before* any write happens — this orchestration lives in `internal/cli.App.inject`. Injecting into an empty vault sets the secret (confirmed by prompting twice, via `Prompter.Prompt(..., confirm=true)`).
- **No stored password.** Secret correctness is enforced purely by AES-GCM authentication failing on `gcm.Open` inside `OpenEntry` — there is no separate password hash to compare.
- **Per-entry salt + nonce.** Every `SealEntry` call generates a fresh random salt (scrypt) and nonce (GCM), even when re-encrypting under the same vault secret.
- **Per-entry scrypt cost.** `SealEntry` records the package's *current* `scryptN`/`R`/`P` consts on the `Entry` itself (`ScryptN`/`ScryptR`/`ScryptP`); `OpenEntry` derives the key from `Entry.scryptParams()` — the entry's own recorded values, falling back to the current consts only when they're zero (an entry from a `vault.*.json` written before this field existed). **Never make `OpenEntry`/`newGCM` use the package consts directly again** — that would break every entry sealed under a cost different from whatever the consts happen to be at read time, which is exactly what this indirection prevents when the consts are later raised.
- **AAD binds vault+entry name.** `aad(env, name)` is passed as AES-GCM additional data, so an entry's ciphertext cannot be decrypted if moved to a different vault or renamed — this is intentional and any refactor must keep signing over both the vault name and entry name (see `TestOpenEntry_AADBindsVaultName`/`AADBindsEntryName`).
- **Multi-file inject is all-or-nothing on read.** `App.inject` reads every source file before writing anything, so a missing source fails before the vault is touched.
- **Folder inject/extract reuse the single-entry paths.** `App.injectDir` (`internal/cli/cli.go`) walks a folder with `filepath.WalkDir` and calls `App.inject` with `<name, absolute-path>` pairs — it doesn't duplicate inject's read-before-write or secret-verification logic. `App.extractDir` is the inverse: it decrypts every entry in the vault before writing any of them, using each entry's name as a path relative to the destination folder. Both require the folder argument to already exist (`os.Stat`, fails before even prompting for a secret if it's missing or not a directory) — extraction does not auto-create the destination the way single-entry `extract` creates missing parent directories.
- **`extractDir`/`extractParent` must recover `OrigName` on the final path component, not just single-entry `extract`.** A top-level entry from a plain, aliased inject (`inject db ./db-password.txt`) has `Entry.Name` == `"db"`, which carries no relation to the real file name — only `Entry.OrigName` does. `cli.withOrigLeaf(relName, origName)` swaps `origName` in as the last slash-separated component of the reconstructed relative path (preserving any directory prefix), so bulk extraction recovers `"db-password.txt"` instead of writing a file literally named `db`. For a folder-injected entry (`Name` = `"alpha/x.txt"`), the leaf already *is* the real file name, so this is a no-op there. Both `extractDir` and `extractParent` must route through `withOrigLeaf` before `safeJoin` — passing raw `e.Name` (or, in `extractParent`, the prefix-trimmed `rel`) straight to `safeJoin` reintroduces the alias-name bug.
- **Folder entry names carry a "parent" prefix — don't drop it.** `App.injectDir` names each entry `<srcFolder base>/<relative path>`, not just `<relative path>`. This is load-bearing, not cosmetic: `Vault.Upsert` matches on `Entry.Name` alone, so without the prefix, injecting two folders that both contain a same-named file would silently overwrite one. `App.extractParent(env, parent, destDir)` selects entries by `strings.HasPrefix(e.Name, parent+"/")` and strips that prefix when writing, so it can pull just one previously injected folder's files back out (into a destDir it creates if missing, unlike `-dir`). Changing `injectDir`'s naming scheme breaks `extractParent`'s matching.
- **`extractDir`/`extractParent` must not trust entry names as safe paths.** Unlike vault names, `Entry.Name` has no `vault.IsValidName`-style pattern enforced on it, so a `../`-shaped or absolute entry name (crafted, or from a hand-edited/older `vault.*.json`) could otherwise resolve outside the destination folder when reconstructed into a path. `cli.safeJoin` guards against this in both — any refactor must keep routing entry-name-to-path joins through it (or an equivalent check) rather than a bare `filepath.Join`.
- **Atomic-ish writes.** `Store.Save` writes to `<path>.tmp` then `os.Rename`s over the target.
- **File permissions matter.** Vault files and extracted output are written `0600` — decrypted/encrypted secrets should never be world-readable; don't loosen this. `vault.CheckFilePermissions`/`Store.CheckPermissions` re-check this on every command that touches a vault (`App.warnLoosePermissions`, `internal/cli/cli.go`) and print an advisory stderr warning if it's since been widened — a Unix-only concept, a no-op on Windows since `os.FileMode` there doesn't reflect real ACLs.
- **Vault name validation.** `vault.IsValidName` restricts names to `[A-Za-z0-9_-]{1,64}` since the name becomes a filename component directly (`Store.PathFor`) — no path separators or `..` allowed. Enforced in `internal/cli.parseVaultFlag` before the name reaches `Store`.
- **Sole-vault auto-default only kicks in when nothing else specified the name.** `parseVaultFlag` now returns `(name, explicit, rest, err)`; when `explicit` is false (no `-vault`/`--vault` flag and no `$VAULT_NAME`), `App.Run` calls `App.defaultVaultName`, which uses the sole `vault.*.json` in `Store.Dir` if there's exactly one, else `"dev"`. This only runs for vault-scoped commands (`!noVaultCmd(args[0])`) — `vaults`/`assets` ignore `env` entirely. An explicit `-vault`/`$VAULT_NAME` always wins, even when a different single vault exists on disk; zero or multiple vaults on disk always fall back to `"dev"` rather than guessing.
- **`Store.Dir` makes storage testable.** Production leaves it empty (current working directory, matching the original single-file behavior); tests set it to `t.TempDir()`. Don't hardcode paths relative to cwd elsewhere in `vault`/`cli`.
- **Secrets are zeroed after use.** `vault.Zero` overwrites a secret (or a KDF-derived key) in place once it's done with. `newGCM` zeroes the derived AES key right after `aes.NewCipher` consumes it; `terminal.Prompter.Prompt` zeroes every buffer it discards along the way; `cli.App.inject`/`extract`/`rotate` `defer vault.Zero(secret)`. Defense-in-depth only — see `DESIGN.md`.
- **Rotation is all-or-nothing.** `Vault.Rotate` re-seals every entry into a separate slice and only assigns it to `v.Entries` once every entry succeeds — a vault is never left with entries split across old and new secrets. `App.rotate` verifies the current secret before even prompting for a new one.
- **`Entry.OrigName` must survive rotation explicitly.** `App.inject` sets `entry.OrigName = filepath.Base(srcFile)` after `SealEntry` returns, so a single extracted file can be written back out under its exact original name (`cli.resolveExtractPath`: when `extract`'s `destPath` is an existing directory, the file is written inside it as `OrigName` instead of requiring `destPath` to already be the literal target file). Because `SealEntry` builds a fresh `Entry` with no knowledge of the source file, `Vault.Rotate` must copy `e.OrigName` onto the newly-sealed entry itself (`sealed.OrigName = e.OrigName`) — omitting that silently loses the original file name on every rotation. `OrigName` is plaintext JSON metadata like `Entry.Name`, not part of the AEAD additional data, and is empty (falls back to `Entry.Name`) for entries injected before this field existed.

## Notes worth remembering

- scrypt parameters are fixed at `N=32768, r=8, p=1` (interactive-login strength) — see the `scrypt*` consts in `internal/vault/vault.go`.
- Minimum secret length is 6 characters (`vault.MinSecretLen`, hard floor), enforced in `internal/terminal.Prompter.Prompt`. `vault.RecommendedSecretLen` (16) + `vault.IsWeakSecret` drive an advisory-only warning when a *new* secret is chosen (`confirm==true`) — it never blocks.
- Exit codes from `cli.App.Run`: `2` = usage/argument error (including invalid vault name), `1` = command ran but failed, `0` = success.
