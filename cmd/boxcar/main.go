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
// package certkey. Alternatively, if HEV_ADDR/HEV_CLIENT_CERT/HEV_CLIENT_KEY/
// HEV_SECRET_PATH are set, the secret is fetched at run time from HashiCorp
// Enterprise Vault (HEV) via an mTLS client certificate — no human ever
// knows the secret at all. See package hevkey.
package main

import (
	"fmt"
	"os"

	"github.com/sanjaynagpal/boxcar/internal/certkey"
	"github.com/sanjaynagpal/boxcar/internal/cli"
	"github.com/sanjaynagpal/boxcar/internal/hevkey"
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
// terminal prompt (terminal.Prompter), which requires a human at a TTY.
// Two non-interactive alternatives are available instead, each gated by its
// own group of env vars, and each fails fast (exit 2) rather than silently
// falling back to a terminal prompt that would just hang or error in a
// non-interactive shell:
//
//   - Cert-wrapped secret: if both $VAULT_KEY_FILE (a PEM RSA private key)
//     and $VAULT_WRAPPED_SECRET (produced by `boxcar cert-wrap`) are set,
//     the secret is unwrapped from those. A human still had to know the
//     secret once, to wrap it. See package certkey.
//   - HEV-backed secret: if $HEV_ADDR, $HEV_CLIENT_CERT, $HEV_CLIENT_KEY,
//     and $HEV_SECRET_PATH are all set, the secret is fetched fresh from
//     HashiCorp Enterprise Vault on every run via an mTLS client
//     certificate — no human ever needs to know it. $HEV_CACERT,
//     $HEV_SECRET_FIELD, $HEV_AUTH_ROLE, and $HEV_NAMESPACE are optional.
//     See package hevkey.
//
// Setting only part of either group, or fully configuring both groups at
// once (ambiguous as to which non-interactive source should win), is
// treated as a misconfiguration.
func buildPrompter() cli.Prompter {
	keyFile := os.Getenv("VAULT_KEY_FILE")
	wrappedFile := os.Getenv("VAULT_WRAPPED_SECRET")
	certWrapConfigured := keyFile != "" && wrappedFile != ""
	if (keyFile != "") != (wrappedFile != "") {
		fmt.Fprintln(os.Stderr, "error: VAULT_KEY_FILE and VAULT_WRAPPED_SECRET must both be set together")
		os.Exit(2)
	}

	hevAddr := os.Getenv("HEV_ADDR")
	hevClientCert := os.Getenv("HEV_CLIENT_CERT")
	hevClientKey := os.Getenv("HEV_CLIENT_KEY")
	hevSecretPath := os.Getenv("HEV_SECRET_PATH")
	hevRequired := []string{hevAddr, hevClientCert, hevClientKey, hevSecretPath}
	hevConfigured := hevAddr != "" && hevClientCert != "" && hevClientKey != "" && hevSecretPath != ""
	hevAnySet := false
	for _, v := range hevRequired {
		if v != "" {
			hevAnySet = true
		}
	}
	if hevAnySet && !hevConfigured {
		fmt.Fprintln(os.Stderr, "error: HEV_ADDR, HEV_CLIENT_CERT, HEV_CLIENT_KEY, and HEV_SECRET_PATH must all be set together")
		os.Exit(2)
	}

	if certWrapConfigured && hevConfigured {
		fmt.Fprintln(os.Stderr, "error: cert-wrap env vars (VAULT_KEY_FILE/VAULT_WRAPPED_SECRET) and HEV env vars (HEV_*) cannot both be set")
		os.Exit(2)
	}

	if certWrapConfigured {
		return certkey.Prompter{WrappedFile: wrappedFile, KeyFile: keyFile}
	}
	if hevConfigured {
		return buildHEVPrompter(hevAddr, hevClientCert, hevClientKey, hevSecretPath)
	}
	return terminal.Prompter{
		Out: os.Stderr,
		FD:  int(os.Stdin.Fd()),
	}
}

// buildHEVPrompter reads the client cert/key (and optional CA bundle) from
// disk and assembles a hevkey.Prompter. It exits like the rest of
// buildPrompter on any file-read failure, since a misconfigured non-
// interactive source should fail fast rather than fall back to a prompt.
func buildHEVPrompter(addr, clientCertFile, clientKeyFile, secretPath string) cli.Prompter {
	clientCertPEM, err := os.ReadFile(clientCertFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read HEV_CLIENT_CERT %q: %v\n", clientCertFile, err)
		os.Exit(2)
	}
	clientKeyPEM, err := os.ReadFile(clientKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read HEV_CLIENT_KEY %q: %v\n", clientKeyFile, err)
		os.Exit(2)
	}
	var caCertPEM []byte
	if caFile := os.Getenv("HEV_CACERT"); caFile != "" {
		caCertPEM, err = os.ReadFile(caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read HEV_CACERT %q: %v\n", caFile, err)
			os.Exit(2)
		}
	}
	return hevkey.Prompter{Config: hevkey.Config{
		Addr:          addr,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		CACertPEM:     caCertPEM,
		SecretPath:    secretPath,
		SecretField:   os.Getenv("HEV_SECRET_FIELD"),
		AuthRole:      os.Getenv("HEV_AUTH_ROLE"),
		Namespace:     os.Getenv("HEV_NAMESPACE"),
	}}
}
