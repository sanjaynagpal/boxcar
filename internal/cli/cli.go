// Package cli implements the boxcar command-line interface: argument
// parsing and command dispatch. It talks to package vault for storage and
// crypto, and to a Prompter for reading secrets, so it has no direct
// terminal dependency and can be exercised in tests.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sanjaynagpal/boxcar/internal/assets"
	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// Prompter reads a secret from the user. When confirm is true the secret is
// read twice and must match both times. The caller owns the returned secret
// and must zero it (vault.Zero) once done with it.
type Prompter interface {
	Prompt(prompt string, confirm bool) ([]byte, error)
}

// App wires together the pieces the CLI needs and dispatches commands.
type App struct {
	Store    vault.Store
	Prompter Prompter
	Stdout   io.Writer
	Stderr   io.Writer
}

// Run parses argv (excluding the program name) and executes the requested
// command, returning a process exit code.
func (a *App) Run(argv []string) int {
	env, args, err := parseVaultFlag(argv)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return 2
	}
	if len(args) < 1 {
		a.usage()
		return 2
	}

	switch args[0] {
	case "vaults":
		err = a.listVaults()
	case "assets":
		err = a.listAssets()
	case "list":
		err = a.listVault(env)
	case "rotate":
		err = a.rotate(env)
	case "inject":
		rest := args[1:]
		if len(rest) < 2 || len(rest)%2 != 0 {
			a.usage()
			return 2
		}
		pairs := make([][2]string, 0, len(rest)/2)
		for i := 0; i < len(rest); i += 2 {
			pairs = append(pairs, [2]string{rest[i], rest[i+1]})
		}
		err = a.inject(env, pairs)
	case "extract":
		if len(args) != 3 {
			a.usage()
			return 2
		}
		err = a.extract(env, args[1], args[2])
	default:
		a.usage()
		return 2
	}

	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return 1
	}
	return 0
}

// parseVaultFlag extracts a leading "-vault <value>" / "-vault=<value>"
// flag, falling back to $VAULT_NAME, then "dev". It returns the resolved
// vault name and the remaining (non-flag) arguments.
func parseVaultFlag(argv []string) (string, []string, error) {
	name := os.Getenv("VAULT_NAME")
	rest := argv
	if len(argv) > 0 {
		a := argv[0]
		switch {
		case a == "-vault" || a == "--vault":
			if len(argv) < 2 {
				return "", nil, fmt.Errorf("%s requires a value", a)
			}
			name, rest = argv[1], argv[2:]
		case strings.HasPrefix(a, "-vault="):
			name, rest = strings.TrimPrefix(a, "-vault="), argv[1:]
		case strings.HasPrefix(a, "--vault="):
			name, rest = strings.TrimPrefix(a, "--vault="), argv[1:]
		}
	}
	if name == "" {
		name = "dev"
	}
	// "vaults"/"assets" don't touch a specific vault; skip validation.
	if len(rest) > 0 && !noVaultCmd(rest[0]) && !vault.IsValidName(name) {
		return "", nil, fmt.Errorf("invalid vault name %q (allowed: letters, digits, _ and -, up to 64 chars)", name)
	}
	return name, rest, nil
}

func noVaultCmd(cmd string) bool {
	return cmd == "vaults" || cmd == "assets"
}

func (a *App) usage() {
	fmt.Fprint(a.Stderr, `boxcar — embedded assets + secret-protected, named vaults

  boxcar [-vault NAME] inject <name> <srcFile> [<name> <srcFile> ...]
                                                    encrypt & append file(s)
  boxcar [-vault NAME] extract <name> <destPath>  decrypt to path
  boxcar [-vault NAME] rotate                     re-encrypt all entries under a new secret
  boxcar [-vault NAME] list                       list entries in a vault
  boxcar vaults                                    list all vaults on disk
  boxcar assets                                    list embedded files

NAME is any of [A-Za-z0-9_-] (max 64 chars) — e.g. dev, prod, team-a, ci.
-vault defaults to $VAULT_NAME, then "dev". Each vault is vault.<NAME>.json.
`)
}

// ---- compile-time embedded assets (read-only) ----

func (a *App) listAssets() error {
	files, err := assets.List()
	if err != nil {
		return err
	}
	for _, f := range files {
		fmt.Fprintln(a.Stdout, f)
	}
	return nil
}

// ---- runtime vault (mutable, secret-protected) ----

// warnLoosePermissions prints a warning to a.Stderr if the named vault's
// sidecar file is readable by group or other. It's best-effort: a stat
// error here shouldn't fail the command that's actually running.
func (a *App) warnLoosePermissions(env string) {
	if msg, err := a.Store.CheckPermissions(env); err == nil && msg != "" {
		fmt.Fprintln(a.Stderr, msg)
	}
}

// inject encrypts one or more files into the named vault under a single
// shared secret. For a new (empty) vault the secret is set here (asked
// twice); for an existing vault the supplied secret is verified against the
// current entries before anything is appended, so a wrong secret is
// rejected up front.
func (a *App) inject(env string, pairs [][2]string) error {
	// Read every source first so a missing file fails before we touch anything.
	plains := make([][]byte, len(pairs))
	for i, p := range pairs {
		data, err := os.ReadFile(p[1])
		if err != nil {
			return fmt.Errorf("read source %q: %w", p[1], err)
		}
		plains[i] = data
	}

	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)

	newVault := len(v.Entries) == 0
	secret, err := a.Prompter.Prompt(fmt.Sprintf("Secret [%s]: ", env), newVault)
	if err != nil {
		return err
	}
	defer vault.Zero(secret)
	if !newVault {
		if err := v.VerifySecret(env, secret); err != nil {
			return err
		}
	}

	for i, p := range pairs {
		entry, err := vault.SealEntry(env, p[0], secret, plains[i])
		if err != nil {
			return err
		}
		v.Upsert(entry)
	}
	if err := a.Store.Save(env, v); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "injected %d file(s) into %s (%d entr%s total)\n",
		len(pairs), env, len(v.Entries), plural(len(v.Entries)))
	return nil
}

func (a *App) extract(env, name, destPath string) error {
	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)
	e, ok := v.Find(name)
	if !ok {
		return fmt.Errorf("no entry named %q", name)
	}

	secret, err := a.Prompter.Prompt(fmt.Sprintf("Secret [%s]: ", env), false)
	if err != nil {
		return err
	}
	defer vault.Zero(secret)
	plain, err := vault.OpenEntry(env, *e, secret)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	// 0600: decrypted secrets should not be world-readable.
	if err := os.WriteFile(destPath, plain, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "extracted %q from %s -> %s (%d bytes)\n", name, env, destPath, len(plain))
	return nil
}

// rotate re-encrypts every entry in the named vault under a freshly chosen
// secret, replacing the current one. The current secret is verified before
// the new one is even asked for, so a wrong current secret is rejected up
// front, and Vault.Rotate itself guarantees the vault is left untouched if
// anything fails partway through.
func (a *App) rotate(env string) error {
	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)
	if len(v.Entries) == 0 {
		return fmt.Errorf("vault %q is empty; nothing to rotate", env)
	}

	oldSecret, err := a.Prompter.Prompt(fmt.Sprintf("Current secret [%s]: ", env), false)
	if err != nil {
		return err
	}
	defer vault.Zero(oldSecret)
	if err := v.VerifySecret(env, oldSecret); err != nil {
		return err
	}

	newSecret, err := a.Prompter.Prompt(fmt.Sprintf("New secret [%s]: ", env), true)
	if err != nil {
		return err
	}
	defer vault.Zero(newSecret)

	if err := v.Rotate(env, oldSecret, newSecret); err != nil {
		return err
	}
	if err := a.Store.Save(env, v); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "rotated secret for %s (%d entr%s)\n", env, len(v.Entries), plural(len(v.Entries)))
	return nil
}

func (a *App) listVault(env string) error {
	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)
	if len(v.Entries) == 0 {
		fmt.Fprintf(a.Stdout, "(%s vault empty)\n", env)
		return nil
	}
	fmt.Fprintf(a.Stdout, "# %s (%s)\n", env, a.Store.PathFor(env))
	for _, e := range v.Entries {
		fmt.Fprintf(a.Stdout, "%-20s %d bytes (encrypted)\n", e.Name, len(e.Ciphertext))
	}
	return nil
}

func (a *App) listVaults() error {
	summaries, err := a.Store.List()
	if err != nil {
		return err
	}
	if len(summaries) == 0 {
		fmt.Fprintln(a.Stdout, "(no vaults yet — create one with: boxcar -vault <name> inject ...)")
		return nil
	}
	for _, s := range summaries {
		status := "unreadable"
		if s.Readable {
			status = fmt.Sprintf("%d entr%s", s.Entries, plural(s.Entries))
		}
		fmt.Fprintf(a.Stdout, "%-20s %-24s (%s)\n", s.Name, s.Path, status)
		if msg, err := vault.CheckFilePermissions(s.Path); err == nil && msg != "" {
			fmt.Fprintln(a.Stderr, msg)
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
