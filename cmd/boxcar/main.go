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
//	boxcar [-vault NAME] cert-wrap <certPEM> <out>   # wrap the secret for non-interactive use
//	boxcar vaults                                    # list all vaults on disk
//
// -vault defaults to VAULT_NAME, then "dev". Each vault is stored in
// vault.<NAME>.json.
//
// Normally the secret is read from a real terminal. If VAULT_KEY_FILE (a
// PEM RSA private key) and VAULT_WRAPPED_SECRET (from cert-wrap) are both
// set, the secret is unwrapped from those instead — no human needed. See
// package certkey.
package main

import (
	"fmt"
	"os"

	"github.com/sanjaynagpal/boxcar/internal/certkey"
	"github.com/sanjaynagpal/boxcar/internal/cli"
	"github.com/sanjaynagpal/boxcar/internal/terminal"
	"github.com/sanjaynagpal/boxcar/internal/vault"
)

func main() {
	app := &cli.App{
		Store:    vault.Store{},
		Prompter: buildPrompter(),
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}
	os.Exit(app.Run(os.Args[1:]))
}

// buildPrompter picks how the secret is obtained. Ordinarily that's a real
// terminal prompt (terminal.Prompter), which requires a human at a TTY. If
// both $VAULT_KEY_FILE (a PEM RSA private key) and $VAULT_WRAPPED_SECRET
// (produced by `boxcar cert-wrap`) are set, boxcar unlocks the vault from
// those instead — no human needed, for CI/cron/deploy scripts. Setting only
// one of the two is treated as a misconfiguration and fails fast rather
// than silently falling back to a terminal prompt that would just hang or
// error in a non-interactive shell.
func buildPrompter() cli.Prompter {
	keyFile := os.Getenv("VAULT_KEY_FILE")
	wrappedFile := os.Getenv("VAULT_WRAPPED_SECRET")
	switch {
	case keyFile != "" && wrappedFile != "":
		return certkey.Prompter{WrappedFile: wrappedFile, KeyFile: keyFile}
	case keyFile != "" || wrappedFile != "":
		fmt.Fprintln(os.Stderr, "error: VAULT_KEY_FILE and VAULT_WRAPPED_SECRET must both be set together")
		os.Exit(2)
	}
	return terminal.Prompter{
		Out: os.Stderr,
		FD:  int(os.Stdin.Fd()),
	}
}
