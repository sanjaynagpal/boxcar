package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// fakePrompter returns secrets from a fixed queue, ignoring the prompt text.
type fakePrompter struct {
	secrets [][]byte
	i       int
}

func (f *fakePrompter) Prompt(prompt string, confirm bool) ([]byte, error) {
	if f.i >= len(f.secrets) {
		panic("fakePrompter: ran out of queued secrets")
	}
	s := f.secrets[f.i]
	f.i++
	return s, nil
}

func newTestApp(t *testing.T, secrets ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	queued := make([][]byte, len(secrets))
	for i, s := range secrets {
		queued[i] = []byte(s)
	}
	var stdout, stderr bytes.Buffer
	app := &App{
		Store:    vault.Store{Dir: t.TempDir()},
		Prompter: &fakePrompter{secrets: queued},
		Stdout:   &stdout,
		Stderr:   &stderr,
	}
	return app, &stdout, &stderr
}

func TestRun_InjectThenExtract(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "injected 1 file(s)") {
		t.Errorf("stdout after inject = %q", stdout.String())
	}
	stdout.Reset()

	dest := filepath.Join(t.TempDir(), "out.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "note", dest}); code != 0 {
		t.Fatalf("extract: code=%d stderr=%s", code, stderr.String())
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("extracted content = %q, want %q", got, "hello world")
	}
}

func TestRun_ExtractIntoDirectoryUsesOriginalFileName(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret", "correct-secret")

	// The entry name ("db") is deliberately unrelated to the source file's
	// own name ("db-password.txt"), the way a user picking a short alias
	// naturally would.
	src := filepath.Join(t.TempDir(), "db-password.txt")
	if err := os.WriteFile(src, []byte("hunter2"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "db", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	destDir := t.TempDir()
	if code := app.Run([]string{"-vault", "dev", "extract", "db", destDir}); code != 0 {
		t.Fatalf("extract: code=%d stderr=%s", code, stderr.String())
	}
	wantPath := filepath.Join(destDir, "db-password.txt")
	if !strings.Contains(stdout.String(), wantPath) {
		t.Errorf("stdout = %q, want it to mention %q", stdout.String(), wantPath)
	}

	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read %s: %v", wantPath, err)
	}
	if string(got) != "hunter2" {
		t.Fatalf("extracted content = %q, want %q", got, "hunter2")
	}

	// A destination that is NOT an existing directory is still honored
	// literally, unchanged from prior behavior.
	exact := filepath.Join(t.TempDir(), "renamed.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "db", exact}); code != 0 {
		t.Fatalf("extract to exact path: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(exact); err != nil {
		t.Fatalf("expected file at exact path %s: %v", exact, err)
	}
}

func TestRun_RotatePreservesOriginalFileName(t *testing.T) {
	app, _, stderr := newTestApp(t,
		"correct-secret", // inject: sets the vault secret
		"correct-secret", // rotate: current secret
		"new-secret-2",   // rotate: new secret
		"new-secret-2",   // extract with the post-rotation secret
	)

	src := filepath.Join(t.TempDir(), "db-password.txt")
	if err := os.WriteFile(src, []byte("hunter2"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "db", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	if code := app.Run([]string{"-vault", "dev", "rotate"}); code != 0 {
		t.Fatalf("rotate: code=%d stderr=%s", code, stderr.String())
	}

	destDir := t.TempDir()
	if code := app.Run([]string{"-vault", "dev", "extract", "db", destDir}); code != 0 {
		t.Fatalf("extract: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(destDir, "db-password.txt")); err != nil {
		t.Fatalf("original file name lost across rotate: %v", err)
	}
}

func TestRun_InjectWrongSecretRejected(t *testing.T) {
	app, _, _ := newTestApp(t, "correct-secret", "wrong-secret!")

	src := filepath.Join(t.TempDir(), "src.txt")
	os.WriteFile(src, []byte("hello"), 0o600)

	if code := app.Run([]string{"-vault", "dev", "inject", "a", src}); code != 0 {
		t.Fatalf("first inject: code=%d", code)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "b", src}); code == 0 {
		t.Fatal("second inject with wrong secret unexpectedly succeeded")
	}
}

func TestRun_InvalidVaultName(t *testing.T) {
	app, _, stderr := newTestApp(t)
	if code := app.Run([]string{"-vault", "has space", "list"}); code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid vault name") {
		t.Errorf("stderr = %q, want mention of invalid vault name", stderr.String())
	}
}

func TestRun_DefaultsToSoleExistingVault(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	// Explicitly create vault.first.json — nothing named "dev".
	if code := app.Run([]string{"-vault", "first", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// No -vault/$VAULT_NAME given: since vault.first.json is the only vault
	// on disk, it should be used instead of defaulting to "dev".
	if code := app.Run([]string{"list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "first") {
		t.Errorf("stdout = %q, want it to reference the first vault", stdout.String())
	}

	dest := filepath.Join(t.TempDir(), "out.txt")
	if code := app.Run([]string{"extract", "note", dest}); code != 0 {
		t.Fatalf("extract: code=%d stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "hello" {
		t.Fatalf("extracted content = %q, %v", got, err)
	}
}

func TestRun_DefaultsToDevWhenNoVaultsExist(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	if code := app.Run([]string{"list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dev vault empty") {
		t.Errorf("stdout = %q, want it to reference the dev vault", stdout.String())
	}
}

func TestRun_DefaultsToDevWhenMultipleVaultsExist(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "alpha", "inject", "note", src}); code != 0 {
		t.Fatalf("inject alpha: code=%d stderr=%s", code, stderr.String())
	}
	if code := app.Run([]string{"-vault", "beta", "inject", "note", src}); code != 0 {
		t.Fatalf("inject beta: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// Two vaults exist and neither is named "dev" — genuinely ambiguous, so
	// this must fall back to "dev" rather than guessing between them.
	if code := app.Run([]string{"list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dev vault empty") {
		t.Errorf("stdout = %q, want it to reference the (empty) dev vault", stdout.String())
	}
}

func TestRun_ExplicitVaultFlagOverridesSoleVaultDefault(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "first", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// Even though "first" is the only vault on disk, an explicit -vault
	// must still be honored rather than overridden by the auto-default.
	if code := app.Run([]string{"-vault", "second", "list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "second vault empty") {
		t.Errorf("stdout = %q, want it to reference the (empty) second vault", stdout.String())
	}
}

func TestRun_NoArgsShowsUsage(t *testing.T) {
	app, _, stderr := newTestApp(t)
	if code := app.Run(nil); code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "boxcar") {
		t.Errorf("stderr = %q, want usage text", stderr.String())
	}
}

func TestRun_ListAssets(t *testing.T) {
	app, stdout, _ := newTestApp(t)
	if code := app.Run([]string{"assets"}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "note.txt") {
		t.Errorf("stdout = %q, want it to list note.txt", stdout.String())
	}
}

func TestRun_ListVaultsEmpty(t *testing.T) {
	app, stdout, _ := newTestApp(t)
	if code := app.Run([]string{"vaults"}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "no vaults yet") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRun_Rotate(t *testing.T) {
	app, stdout, stderr := newTestApp(t,
		"correct-secret", // inject: sets the vault secret
		"correct-secret", // rotate: current secret
		"new-secret-2",   // rotate: new secret
		"correct-secret", // extract attempt with the pre-rotation secret (expect failure)
		"new-secret-2",   // extract attempt with the post-rotation secret (expect success)
	)

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	if code := app.Run([]string{"-vault", "dev", "rotate"}); code != 0 {
		t.Fatalf("rotate: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rotated secret") {
		t.Errorf("stdout after rotate = %q", stdout.String())
	}

	destOld := filepath.Join(t.TempDir(), "old.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "note", destOld}); code == 0 {
		t.Fatal("extract with the pre-rotation secret unexpectedly succeeded")
	}

	destNew := filepath.Join(t.TempDir(), "new.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "note", destNew}); code != 0 {
		t.Fatalf("extract with the post-rotation secret: code=%d stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(destNew)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("extracted content = %q, want %q", got, "hello world")
	}
}

func TestRun_RotateWrongOldSecretRejected(t *testing.T) {
	app, _, _ := newTestApp(t,
		"correct-secret", // inject
		"wrong-secret!",  // rotate: wrong current secret — rejected before a new one is even asked for
		"correct-secret", // extract: original secret must still work
	)

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d", code)
	}
	if code := app.Run([]string{"-vault", "dev", "rotate"}); code == 0 {
		t.Fatal("rotate with the wrong current secret unexpectedly succeeded")
	}

	dest := filepath.Join(t.TempDir(), "out.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "note", dest}); code != 0 {
		t.Fatal("extract with the original secret failed after a rejected rotate attempt")
	}
}

func TestRun_RotateEmptyVault(t *testing.T) {
	app, _, stderr := newTestApp(t)
	if code := app.Run([]string{"-vault", "dev", "rotate"}); code == 0 {
		t.Fatal("rotate on an empty vault unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "nothing to rotate") {
		t.Errorf("stderr = %q, want mention of nothing to rotate", stderr.String())
	}
}

func TestRun_WarnsOnLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits aren't real ACLs on Windows")
	}

	app, _, stderr := newTestApp(t, "correct-secret")
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stderr.Reset()

	if err := os.Chmod(app.Store.PathFor("dev"), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "readable by group/other") {
		t.Errorf("stderr = %q, want a loose-permissions warning", stderr.String())
	}
}

func TestRun_ExtractUnknownEntry(t *testing.T) {
	app, _, _ := newTestApp(t)
	dest := filepath.Join(t.TempDir(), "out.txt")
	if code := app.Run([]string{"-vault", "dev", "extract", "missing", dest}); code == 0 {
		t.Fatal("extracting a missing entry unexpectedly succeeded")
	}
}

func TestRun_InjectDirThenExtractDir(t *testing.T) {
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret")

	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("top-level"), 0o600); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("nested"), 0o600); err != nil {
		t.Fatalf("write sub/b.txt: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "inject", "-dir", srcDir}); code != 0 {
		t.Fatalf("inject -dir: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "injected 2 file(s)") {
		t.Errorf("stdout after inject -dir = %q", stdout.String())
	}
	stdout.Reset()

	destDir := t.TempDir()
	if code := app.Run([]string{"-vault", "dev", "extract", "-dir", destDir}); code != 0 {
		t.Fatalf("extract -dir: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "extracted 2 file(s)") {
		t.Errorf("stdout after extract -dir = %q", stdout.String())
	}

	// Entry names are prefixed with srcDir's own base name (its "parent"),
	// so a full -dir extract recreates that folder as a subdirectory of
	// destDir rather than flattening its contents into destDir directly.
	parent := filepath.Base(srcDir)
	got, err := os.ReadFile(filepath.Join(destDir, parent, "a.txt"))
	if err != nil || string(got) != "top-level" {
		t.Fatalf("%s/a.txt = %q, %v", parent, got, err)
	}
	got, err = os.ReadFile(filepath.Join(destDir, parent, "sub", "b.txt"))
	if err != nil || string(got) != "nested" {
		t.Fatalf("%s/sub/b.txt = %q, %v", parent, got, err)
	}
}

func TestRun_ExtractDirUsesOriginalFileNameForTopLevelEntries(t *testing.T) {
	// A vault holding both a plain, aliased top-level inject and a
	// folder-injected entry: extract -dir must recover the real file name
	// for the top-level entry (its entry name, "db", is just an alias) and
	// leave the folder entry's already-correct name alone.
	app, stdout, stderr := newTestApp(t, "correct-secret", "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "db-password.txt")
	if err := os.WriteFile(src, []byte("hunter2"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "db", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}

	srcDir := filepath.Join(t.TempDir(), "alpha")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "x.txt"), []byte("alpha-x"), 0o600); err != nil {
		t.Fatalf("write alpha/x.txt: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "-dir", srcDir}); code != 0 {
		t.Fatalf("inject -dir: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	destDir := t.TempDir()
	if code := app.Run([]string{"-vault", "dev", "extract", "-dir", destDir}); code != 0 {
		t.Fatalf("extract -dir: code=%d stderr=%s", code, stderr.String())
	}

	got, err := os.ReadFile(filepath.Join(destDir, "db-password.txt"))
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("top-level entry: db-password.txt = %q, %v (want original file name preserved)", got, err)
	}
	if _, err := os.Stat(filepath.Join(destDir, "db")); err == nil {
		t.Fatal("top-level entry was written under its alias name \"db\" instead of its original file name")
	}
	got, err = os.ReadFile(filepath.Join(destDir, "alpha", "x.txt"))
	if err != nil || string(got) != "alpha-x" {
		t.Fatalf("folder entry: alpha/x.txt = %q, %v", got, err)
	}
}

func TestRun_InjectDirNamesPreventCollisionsAndExtractParent(t *testing.T) {
	// Mirrors the real scenario this feature is for: a vault populated from
	// two different folders (each contributing files that could otherwise
	// collide by bare name) plus two individually named files. Extracting
	// by parent should pull out only the files that came from that one
	// folder, not everything in the vault.
	app, stdout, stderr := newTestApp(t,
		"correct-secret", // inject alpha (sets the vault secret)
		"correct-secret", // inject beta
		"correct-secret", // inject individual files
		"correct-secret", // extract -parent alpha
	)

	root := t.TempDir()
	alpha := filepath.Join(root, "alpha")
	beta := filepath.Join(root, "beta")
	for _, dir := range []string{alpha, beta} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	// Both folders contain a same-named file, to prove they don't collide
	// once prefixed with their parent folder name.
	if err := os.WriteFile(filepath.Join(alpha, "x.txt"), []byte("alpha-x"), 0o600); err != nil {
		t.Fatalf("write alpha/x.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(alpha, "y.txt"), []byte("alpha-y"), 0o600); err != nil {
		t.Fatalf("write alpha/y.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(beta, "x.txt"), []byte("beta-x"), 0o600); err != nil {
		t.Fatalf("write beta/x.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(beta, "z.txt"), []byte("beta-z"), 0o600); err != nil {
		t.Fatalf("write beta/z.txt: %v", err)
	}

	if code := app.Run([]string{"-vault", "dev", "inject", "-dir", alpha}); code != 0 {
		t.Fatalf("inject alpha: code=%d stderr=%s", code, stderr.String())
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "-dir", beta}); code != 0 {
		t.Fatalf("inject beta: code=%d stderr=%s", code, stderr.String())
	}

	individual1 := filepath.Join(root, "one.txt")
	individual2 := filepath.Join(root, "two.txt")
	if err := os.WriteFile(individual1, []byte("indiv-1"), 0o600); err != nil {
		t.Fatalf("write one.txt: %v", err)
	}
	if err := os.WriteFile(individual2, []byte("indiv-2"), 0o600); err != nil {
		t.Fatalf("write two.txt: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "one", individual1, "two", individual2}); code != 0 {
		t.Fatalf("inject individual files: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	if code := app.Run([]string{"-vault", "dev", "list"}); code != 0 {
		t.Fatalf("list: code=%d stderr=%s", code, stderr.String())
	}
	if got := strings.Count(stdout.String(), "\n") - 1; got != 6 { // -1 for the "# dev (...)" header line
		t.Fatalf("vault has %d entries, want 6:\n%s", got, stdout.String())
	}
	stdout.Reset()

	// destAlpha deliberately does not exist yet — extractParent must create it.
	destAlpha := filepath.Join(t.TempDir(), "alpha-bak")
	if code := app.Run([]string{"-vault", "dev", "extract", "-parent", "alpha", destAlpha}); code != 0 {
		t.Fatalf("extract -parent alpha: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "extracted 2 file(s)") {
		t.Errorf("stdout after extract -parent = %q", stdout.String())
	}

	entries, err := os.ReadDir(destAlpha)
	if err != nil {
		t.Fatalf("read destAlpha: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("destAlpha has %d entries, want 2", len(entries))
	}
	got, err := os.ReadFile(filepath.Join(destAlpha, "x.txt"))
	if err != nil || string(got) != "alpha-x" {
		t.Fatalf("alpha-bak/x.txt = %q, %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(destAlpha, "y.txt"))
	if err != nil || string(got) != "alpha-y" {
		t.Fatalf("alpha-bak/y.txt = %q, %v", got, err)
	}
}

func TestRun_ExtractParentUnknown(t *testing.T) {
	app, _, stderr := newTestApp(t, "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d", code)
	}

	dest := filepath.Join(t.TempDir(), "out")
	if code := app.Run([]string{"-vault", "dev", "extract", "-parent", "nope", dest}); code == 0 {
		t.Fatal("extract -parent for an unknown parent unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), `no entries found under parent "nope"`) {
		t.Errorf("stderr = %q, want mention of no entries found", stderr.String())
	}
}

func TestRun_InjectDirMissingFolder(t *testing.T) {
	app, _, stderr := newTestApp(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if code := app.Run([]string{"-vault", "dev", "inject", "-dir", missing}); code == 0 {
		t.Fatal("inject -dir on a missing folder unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Errorf("stderr = %q, want mention of missing folder", stderr.String())
	}
}

func TestRun_ExtractDirMissingFolder(t *testing.T) {
	app, _, stderr := newTestApp(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if code := app.Run([]string{"-vault", "dev", "extract", "-dir", missing}); code == 0 {
		t.Fatal("extract -dir into a missing folder unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Errorf("stderr = %q, want mention of missing folder", stderr.String())
	}
}

func TestRun_ExtractDirRejectsUnsafeEntryName(t *testing.T) {
	app, _, stderr := newTestApp(t, "correct-secret", "correct-secret")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	// Entry names aren't restricted the way vault names are, so inject a
	// traversal-shaped name directly via the pairs form to simulate a
	// crafted or corrupted entry.
	if code := app.Run([]string{"-vault", "dev", "inject", "../escape", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}

	destDir := t.TempDir()
	if code := app.Run([]string{"-vault", "dev", "extract", "-dir", destDir}); code == 0 {
		t.Fatal("extract -dir with an unsafe entry name unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "unsafe entry name") {
		t.Errorf("stderr = %q, want mention of unsafe entry name", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(destDir), "escape")); err == nil {
		t.Fatal("file was written outside destDir")
	}
}
