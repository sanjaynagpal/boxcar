# Boxcar

A single-binary Go CLI that combines two storage models:

- **Compile-time embedded assets** (`go:embed`) — static files baked into
  the binary, read-only.
- **Runtime, secret-protected vaults** — named, encrypted sidecar files
  (`vault.<NAME>.json`) you can inject files into and later extract from
  with the correct secret.

Go's `embed.FS` can't be written to at runtime, so the two storage models
are deliberately separate — see `DESIGN.md` for why.

## Use cases

- **Carrying secrets alongside a distributed binary** — API keys, `.env`
  files, SSH keys, TLS certs, DB credentials — encrypted in
  `vault.<NAME>.json` next to the executable, decrypted only with the
  shared secret, instead of baked into the binary or left in a plain env
  var.
- **Per-environment secret sets** — named vaults (`dev`, `staging`, `prod`,
  `team-a`) keep credentials for different environments fully isolated,
  each with its own secret and its own file.
- **Offline / air-gapped secret transport** — no server or network
  dependency; copy the `vault.*.json` file to another machine and decrypt
  there with the shared secret.
- **Grouped secret bundles by source folder** — `inject -dir` /
  `extract -parent` suit per-service or per-component credential bundles:
  inject a whole folder of one service's config/secrets, later pull just
  that service's files back out.
- **Secret rotation without redistribution** — `rotate` re-encrypts every
  entry under a new secret in place, without needing to re-inject every
  file.
- **A minimal personal or small-team secrets vault** — lighter-weight than
  running a full secrets manager, for "encrypt these files, decrypt with a
  password later."

## Install

```
go build -o boxcar ./cmd/boxcar
```

Or, against this module directly:

```
go install github.com/sanjaynagpal/boxcar/cmd/boxcar@latest
```

Requires Go 1.26+ (or any Go with `GOTOOLCHAIN=auto`, the default since Go
1.21, which transparently downloads 1.26 for this module if your installed
`go` is older).

## Quick start

```
boxcar -vault dev inject db-password ./password.txt   # creates the vault, prompts for a secret
boxcar -vault dev inject -dir ./secrets/alpha           # inject every file under alpha, recursively;
                                                          # entries are named "alpha/<relative path>"
boxcar -vault dev list                                 # see what's in it (never plaintext)
boxcar -vault dev extract db-password ./restored.txt   # decrypt back out, prompts for the secret
boxcar -vault dev extract db-password ./restored/       # or drop it into a folder under its
                                                          # original file name, e.g. ./restored/password.txt
boxcar -vault dev extract -dir ./restored               # decrypt every entry back into ./restored
boxcar -vault dev extract -parent alpha ./alpha-bak     # decrypt only "alpha/..." entries into
                                                          # ./alpha-bak (created if missing), stripping
                                                          # the "alpha/" prefix
boxcar -vault dev rotate                                # replace the vault's secret
boxcar vaults                                           # every vault.*.json on disk
boxcar assets                                           # files embedded at compile time
```

`-vault NAME` selects which vault a command operates on, falling back to
`$VAULT_NAME`; if neither is given and exactly one `vault.*.json` exists in
the current directory, that vault is used automatically — otherwise (no
vaults yet, or more than one) it falls back to `dev`. Vaults are fully
isolated from each other — each is its own file, its own secret, its own
entries.

## Non-interactive use (CI, cron, deploy scripts)

By default the secret is read from a real terminal, which needs a human at
the keyboard. For automation, wrap the vault's secret once to an RSA
certificate's public key, then hand the wrapped file and matching private
key to boxcar instead of a human typing anything. Only RSA certificates/keys
are currently supported; see `internal/certkey` for the envelope-encryption
scheme.

### Quick version

```
boxcar -vault dev cert-wrap ./cert.pem ./dev.wrapped.json   # one-time, interactive: asks for
                                                              # the vault's current secret
export VAULT_KEY_FILE=./private-key.pem         # PEM-encoded RSA private key matching cert.pem
export VAULT_WRAPPED_SECRET=./dev.wrapped.json  # produced by cert-wrap above
boxcar -vault dev extract db-password ./restored.txt   # no prompt — unlocked from the files above
```

Both env vars must be set together (setting only one is treated as a
misconfiguration and fails fast).

### Full walkthrough: generating a cert and deploying it safely

The private key above is itself sensitive — the whole scheme falls apart if
it's just a bare `.pem` file sitting in a git repo or an unencrypted backup.
Boxcar can generate that cert/key pair and then use its *own* vault
mechanism to protect the pair in transit, so the only thing that ever needs
to leave your machine as plaintext is the (non-secret) public certificate:

```
# 1. Generate a fresh self-signed RSA cert/key pair.
boxcar cert-gen ./certs                          # -> ./certs/cert.pem, ./certs/key.pem

# 2. Bundle the pair into its OWN password-protected vault — this is what
#    actually gets copied to the server, not the bare key file.
boxcar -vault keyvault inject -dir ./certs        # prompts for a new password, twice

# 3. Populate the real vault holding your application secrets, same as usual.
boxcar -vault prod inject db-password ./db-password.txt

# 4. Wrap prod's secret to the certificate's public key.
boxcar -vault prod cert-wrap ./certs/cert.pem ./prod.wrapped.json
```

What to copy to the server: `vault.keyvault.json`, `vault.prod.json`, and
`prod.wrapped.json`. None of these are plaintext — `vault.keyvault.json`
still needs the keyvault password to open.

```
# 5. On the server, ONE TIME, with a human present: recover the private key.
mkdir ./recovered
boxcar -vault keyvault extract -dir ./recovered   # prompts for the keyvault password
#   -> ./recovered/certs/cert.pem, ./recovered/certs/key.pem

# 6. From then on, every run is fully non-interactive:
export VAULT_KEY_FILE=./recovered/certs/key.pem
export VAULT_WRAPPED_SECRET=./prod.wrapped.json
boxcar -vault prod extract db-password ./restored.txt   # no prompt at all
```

Step 5 is the only human-in-the-loop moment in this whole flow, and it only
has to happen once per server (or once per key rotation) — every
subsequent `inject`/`extract`/`rotate` against `prod` on that server runs
unattended.

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
