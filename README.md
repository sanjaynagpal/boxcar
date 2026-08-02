# Boxcar

A single-binary Go CLI that combines two storage models:

- **Compile-time embedded assets** (`go:embed`) — static files baked into
  the binary, read-only.
- **Runtime, secret-protected vaults** — named, encrypted sidecar files
  (`vault.<NAME>.json`) you can inject files into and later extract from
  with the correct secret.

Go's `embed.FS` can't be written to at runtime, so the two storage models
are deliberately separate — see `DESIGN.md` for why.

## Install

```
go build -o boxcar ./cmd/boxcar
```

Or, against this module directly:

```
go install github.com/sanjaynagpal/boxcar/cmd/boxcar@latest
```

Requires Go 1.22+.

## Quick start

```
boxcar -vault dev inject db-password ./password.txt   # creates the vault, prompts for a secret
boxcar -vault dev list                                 # see what's in it (never plaintext)
boxcar -vault dev extract db-password ./restored.txt   # decrypt back out, prompts for the secret
boxcar -vault dev rotate                                # replace the vault's secret
boxcar vaults                                           # every vault.*.json on disk
boxcar assets                                           # files embedded at compile time
```

`-vault NAME` selects which vault a command operates on (falls back to
`$VAULT_NAME`, then `dev`). Vaults are fully isolated from each other —
each is its own file, its own secret, its own entries.

## Security, briefly

- Encryption: AES-256-GCM; key derivation: scrypt with a random per-entry
  salt. No password is ever stored — a wrong secret fails AEAD
  authentication, which is what actually proves a secret is correct.
- Every entry's ciphertext is bound (via AEAD additional data) to its
  vault name and entry name, so it can't be moved or renamed outside the
  tool without decryption failing.
- Vault and extracted files are written `0600`; every command re-checks
  and warns if that's since been loosened.

Full threat model, what's mitigated, and what isn't: `DESIGN.md`.

## Documentation

| File | For |
|---|---|
| `RUNBOOK.md` | Operating boxcar day to day — procedures, troubleshooting, incident response |
| `DESIGN.md` | Architecture, package layout, and the full security threat model |
| `REQUIREMENTS.md` | The functional and security spec |
| `CLAUDE.md` | Guidance for AI coding assistants working in this repo |

## Development

```
go build ./...
go vet ./...
go test ./...
```

See `CLAUDE.md` for the fuller developer-facing guide, including
architecture and single-test invocation.

## License

MIT — see `LICENSE`.
