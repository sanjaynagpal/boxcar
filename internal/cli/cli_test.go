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
