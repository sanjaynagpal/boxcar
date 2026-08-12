// Package cli implements the boxcar command-line interface: argument
// parsing and command dispatch. It talks to package vault for storage and
// crypto, and to a Prompter for reading secrets, so it has no direct
// terminal dependency and can be exercised in tests.
package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
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
	env, explicit, args, err := parseVaultFlag(argv)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error:", err)
		return 2
	}
	if len(args) < 1 {
		a.usage()
		return 2
	}
	if !explicit && !noVaultCmd(args[0]) {
		env = a.defaultVaultName()
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
		if len(rest) == 2 && rest[0] == "-dir" {
			err = a.injectDir(env, rest[1])
			break
		}
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
		rest := args[1:]
		if len(rest) == 2 && rest[0] == "-dir" {
			err = a.extractDir(env, rest[1])
			break
		}
		if len(rest) == 3 && rest[0] == "-parent" {
			err = a.extractParent(env, rest[1], rest[2])
			break
		}
		if len(rest) != 2 {
			a.usage()
			return 2
		}
		err = a.extract(env, rest[0], rest[1])
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
// flag, falling back to $VAULT_NAME. It returns the resolved vault name (if
// any), whether that name was explicitly given (by flag or env var, as
// opposed to left for Run to default), and the remaining (non-flag)
// arguments. When explicit is false, name is "" and it's up to the caller
// to pick a default (see App.defaultVaultName).
func parseVaultFlag(argv []string) (name string, explicit bool, rest []string, err error) {
	rest = argv
	if len(argv) > 0 {
		a := argv[0]
		switch {
		case a == "-vault" || a == "--vault":
			if len(argv) < 2 {
				return "", false, nil, fmt.Errorf("%s requires a value", a)
			}
			name, rest = argv[1], argv[2:]
			explicit = true
		case strings.HasPrefix(a, "-vault="):
			name, rest = strings.TrimPrefix(a, "-vault="), argv[1:]
			explicit = true
		case strings.HasPrefix(a, "--vault="):
			name, rest = strings.TrimPrefix(a, "--vault="), argv[1:]
			explicit = true
		}
	}
	if !explicit {
		if envName := os.Getenv("VAULT_NAME"); envName != "" {
			name, explicit = envName, true
		}
	}
	// "vaults"/"assets" don't touch a specific vault; skip validation.
	if explicit && len(rest) > 0 && !noVaultCmd(rest[0]) && !vault.IsValidName(name) {
		return "", false, nil, fmt.Errorf("invalid vault name %q (allowed: letters, digits, _ and -, up to 64 chars)", name)
	}
	return name, explicit, rest, nil
}

// defaultVaultName picks the vault to use when the caller didn't specify one
// via -vault or $VAULT_NAME: if exactly one vault.<name>.json exists in the
// store's directory, that vault's name is used, so a directory holding a
// single, differently-named vault (e.g. vault.first.json) doesn't force the
// user to spell out -vault every time. Otherwise (no vaults yet, or more
// than one — genuinely ambiguous) it falls back to "dev", the long-standing
// default, rather than guessing.
func (a *App) defaultVaultName() string {
	summaries, err := a.Store.List()
	if err != nil || len(summaries) != 1 {
		return "dev"
	}
	if !vault.IsValidName(summaries[0].Name) {
		return "dev"
	}
	return summaries[0].Name
}

func noVaultCmd(cmd string) bool {
	return cmd == "vaults" || cmd == "assets"
}

func (a *App) usage() {
	fmt.Fprint(a.Stderr, `boxcar — embedded assets + secret-protected, named vaults

  boxcar [-vault NAME] inject <name> <srcFile> [<name> <srcFile> ...]
                                                    encrypt & append file(s)
  boxcar [-vault NAME] inject -dir <srcFolder>    encrypt & append every file
                                                    in srcFolder (recursive);
                                                    entry names are
                                                    "<srcFolder base>/<relative
                                                    path>", so files from
                                                    different folders (or from
                                                    a folder vs. an individual
                                                    inject) don't collide
  boxcar [-vault NAME] extract <name> <destPath>  decrypt to path; if
                                                    destPath is an existing
                                                    folder, the file is
                                                    written inside it under
                                                    its original source file
                                                    name
  boxcar [-vault NAME] extract -dir <destFolder>  decrypt every entry into
                                                    destFolder, recreating
                                                    each entry's name as a
                                                    relative path
  boxcar [-vault NAME] extract -parent <name> <destFolder>
                                                    decrypt only the entries
                                                    injected from the folder
                                                    named <name> (via
                                                    inject -dir) into
                                                    destFolder, stripping the
                                                    "<name>/" prefix; creates
                                                    destFolder if it doesn't
                                                    exist
  boxcar [-vault NAME] rotate                     re-encrypt all entries under a new secret
  boxcar [-vault NAME] list                       list entries in a vault
  boxcar vaults                                    list all vaults on disk
  boxcar assets                                    list embedded files

NAME is any of [A-Za-z0-9_-] (max 64 chars) — e.g. dev, prod, team-a, ci.
-vault defaults to $VAULT_NAME; if neither is set and exactly one
vault.*.json exists in the current directory, that vault is used, else
"dev". Each vault is vault.<NAME>.json.
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
		entry.OrigName = filepath.Base(p[1])
		v.Upsert(entry)
	}
	if err := a.Store.Save(env, v); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "injected %d file(s) into %s (%d entr%s total)\n",
		len(pairs), env, len(v.Entries), plural(len(v.Entries)))
	return nil
}

// injectDir walks srcDir recursively and injects every regular file it
// finds. Each entry's name is srcDir's own base name (its "parent") joined
// with the file's slash-separated path relative to srcDir, e.g. injecting
// ".../alpha" containing "x.txt" and "sub/y.txt" produces entries
// "alpha/x.txt" and "alpha/sub/y.txt". Recording the parent this way keeps
// folders injected under different source names from colliding on entry
// name (two folders both containing "x.txt" would otherwise overwrite one
// another via Upsert) and is what lets extractParent later pull just one
// folder's files back out. It delegates to inject, so the same
// all-or-nothing read-before-write and secret-verification behavior
// applies.
func (a *App) injectDir(env, srcDir string) error {
	info, err := os.Stat(srcDir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("source folder %q does not exist", srcDir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source path %q is not a folder", srcDir)
	}
	parent := filepath.Base(filepath.Clean(srcDir))

	var pairs [][2]string
	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(parent, rel))
		pairs = append(pairs, [2]string{name, path})
		return nil
	})
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		return fmt.Errorf("source folder %q contains no files", srcDir)
	}
	return a.inject(env, pairs)
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
	destPath = resolveExtractPath(*e, destPath)

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

// resolveExtractPath returns the path extract should actually write to:
// destPath unchanged, unless it already names an existing directory, in
// which case the file is written inside it under e's original source file
// name (e.OrigName) — falling back to e.Name itself for entries injected
// before OrigName existed. This lets `extract <name> <destFolder>` drop the
// file in with its exact original name without the caller needing to
// already know or retype it, while `extract <name> <exact/file/path>`
// keeps writing to precisely the path given, unchanged.
func resolveExtractPath(e vault.Entry, destPath string) string {
	info, err := os.Stat(destPath)
	if err != nil || !info.IsDir() {
		return destPath
	}
	filename := e.OrigName
	if filename == "" {
		filename = e.Name
	}
	return filepath.Join(destPath, filename)
}

// extractDir decrypts every entry in the named vault into destDir,
// recreating each entry's name as a path relative to destDir (mirroring
// injectDir's use of relative paths as entry names), with the final path
// component replaced by the entry's recorded original source file name
// (see withOrigLeaf) — so a plain, aliased inject (e.g. `inject db
// ./db-password.txt`) extracts back out as "db-password.txt", not "db",
// while a folder-injected entry (whose name's own leaf already is the real
// file name) is unaffected. Every entry is decrypted first so a wrong
// secret or an unsafe entry name fails before any file is written.
func (a *App) extractDir(env, destDir string) error {
	info, err := os.Stat(destDir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("destination folder %q does not exist", destDir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("destination path %q is not a folder", destDir)
	}

	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)
	if len(v.Entries) == 0 {
		return fmt.Errorf("vault %q is empty; nothing to extract", env)
	}

	secret, err := a.Prompter.Prompt(fmt.Sprintf("Secret [%s]: ", env), false)
	if err != nil {
		return err
	}
	defer vault.Zero(secret)

	type decrypted struct {
		path string
		data []byte
	}
	files := make([]decrypted, 0, len(v.Entries))
	for _, e := range v.Entries {
		destPath, err := safeJoin(destDir, withOrigLeaf(e.Name, e.OrigName))
		if err != nil {
			return fmt.Errorf("entry %q: %w", e.Name, err)
		}
		plain, err := vault.OpenEntry(env, e, secret)
		if err != nil {
			return fmt.Errorf("entry %q: %w", e.Name, err)
		}
		files = append(files, decrypted{path: destPath, data: plain})
	}

	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return err
		}
		// 0600: decrypted secrets should not be world-readable.
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.Stdout, "extracted %d file(s) from %s -> %s\n", len(files), env, destDir)
	return nil
}

// extractParent decrypts only the entries recorded under the given parent
// folder — i.e. names of the form "parent/..." as produced by injectDir —
// into destDir, stripping the "parent/" prefix so destDir mirrors the
// original source folder's own layout rather than nesting it under a
// "parent" subdirectory. Unlike extractDir/injectDir's folder arguments,
// destDir does not need to already exist: since the point of this command is
// to recreate one specific folder's contents, boxcar creates it (and any
// intermediate directories) automatically. As with extractDir, every
// matching entry is decrypted before anything is written, so a wrong secret
// or an unsafe entry name is rejected before any file lands on disk.
func (a *App) extractParent(env, parent, destDir string) error {
	v, err := a.Store.Load(env)
	if err != nil {
		return err
	}
	a.warnLoosePermissions(env)

	prefix := parent + "/"
	var matches []vault.Entry
	for _, e := range v.Entries {
		if strings.HasPrefix(e.Name, prefix) {
			matches = append(matches, e)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("no entries found under parent %q", parent)
	}

	secret, err := a.Prompter.Prompt(fmt.Sprintf("Secret [%s]: ", env), false)
	if err != nil {
		return err
	}
	defer vault.Zero(secret)

	type decrypted struct {
		path string
		data []byte
	}
	files := make([]decrypted, 0, len(matches))
	for _, e := range matches {
		rel := strings.TrimPrefix(e.Name, prefix)
		destPath, err := safeJoin(destDir, withOrigLeaf(rel, e.OrigName))
		if err != nil {
			return fmt.Errorf("entry %q: %w", e.Name, err)
		}
		plain, err := vault.OpenEntry(env, e, secret)
		if err != nil {
			return fmt.Errorf("entry %q: %w", e.Name, err)
		}
		files = append(files, decrypted{path: destPath, data: plain})
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return err
		}
		// 0600: decrypted secrets should not be world-readable.
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.Stdout, "extracted %d file(s) under parent %q from %s -> %s\n",
		len(files), parent, env, destDir)
	return nil
}

// withOrigLeaf replaces the final slash-separated component of relName with
// origName, preserving any directory prefix, e.g.
// withOrigLeaf("alpha/x.txt", "x.txt") == "alpha/x.txt" and
// withOrigLeaf("db", "db-password.txt") == "db-password.txt". Returns
// relName unchanged if origName is empty (entries injected before OrigName
// existed). For a folder-injected entry, relName's own leaf already is the
// real source file name, so this is a no-op; for a plain aliased inject
// (relName is an arbitrary name unrelated to any real file) it's what
// recovers the original file name on bulk extraction.
func withOrigLeaf(relName, origName string) string {
	if origName == "" {
		return relName
	}
	dir := path.Dir(relName)
	if dir == "." {
		return origName
	}
	return dir + "/" + origName
}

// safeJoin joins base with a slash-separated entry name, rejecting any name
// that would resolve outside base (an absolute path, "..", or a leading
// "../"). Unlike vault names, entry names aren't restricted to
// vault.IsValidName's safe-filename pattern, so extractDir must guard
// against a crafted or corrupted entry name escaping destDir.
func safeJoin(base, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe entry name %q", name)
	}
	return filepath.Join(base, clean), nil
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
