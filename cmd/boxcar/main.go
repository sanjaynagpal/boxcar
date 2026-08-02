// Command boxcar demonstrates:
//   - a compile-time embed.FS holding static assets (read-only)
//   - a runtime-mutable "vault" where a user can inject a file protected
//     by a secret, then later extract it to a path with the correct secret.
//
// Key point: Go's embed.FS is READ-ONLY and fixed at build time. You cannot
// write into it at runtime. The injected file is therefore stored in a
// separate, mutable store (see package vault) — a sidecar vault.json next
// to the binary.
//
// Each named vault gets its OWN sidecar file, selected with -vault (or the
// VAULT_NAME variable). Any name matching [A-Za-z0-9_-] works — dev/test/prod,
// but also team-a, ci, staging, etc. Entries and secrets are isolated per
// vault: a name injected into "prod" is invisible to "dev", and the prod
// secret only decrypts prod entries.
//
// Usage:
//
//	boxcar [-vault NAME] assets                     # list embedded files
//	boxcar [-vault NAME] inject <name> <srcFile>...  # append file(s)
//	boxcar [-vault NAME] extract <name> <dest>       # prompts for the secret
//	boxcar [-vault NAME] list                        # list injected entries
//	boxcar vaults                                    # list all vaults on disk
//
// -vault defaults to VAULT_NAME, then "dev". Each vault is stored in
// vault.<NAME>.json.
package main

import (
	"os"

	"github.com/sanjaynagpal/boxcar/internal/cli"
	"github.com/sanjaynagpal/boxcar/internal/terminal"
	"github.com/sanjaynagpal/boxcar/internal/vault"
)

func main() {
	app := &cli.App{
		Store: vault.Store{},
		Prompter: terminal.Prompter{
			Out: os.Stderr,
			FD:  int(os.Stdin.Fd()),
		},
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	os.Exit(app.Run(os.Args[1:]))
}
