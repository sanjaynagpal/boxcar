package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sanjaynagpal/boxcar/internal/certkey"
	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// genRSACert returns a self-signed RSA cert/key pair PEM-encoded, for
// exercising cert-wrap without checking in static key material. It's a
// thin wrapper over certkey.GenerateSelfSigned (the same function cert-gen
// itself calls) so tests exercise real production cert-generation logic
// instead of duplicating it.
func genRSACert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM, err := certkey.GenerateSelfSigned("test")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	return certPEM, keyPEM
}

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

func TestRun_CertGenCreatesUsableCertAndKey(t *testing.T) {
	app, stdout, stderr := newTestApp(t)

	// outDir deliberately does not exist yet — cert-gen must create it,
	// unlike inject -dir/extract -dir which require the folder to pre-exist.
	outDir := filepath.Join(t.TempDir(), "certs")
	if code := app.Run([]string{"cert-gen", outDir}); code != 0 {
		t.Fatalf("cert-gen: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), outDir) {
		t.Errorf("stdout = %q, want it to mention %q", stdout.String(), outDir)
	}

	certPEM, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read cert.pem: %v", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(outDir, "key.pem"))
	if err != nil {
		t.Fatalf("read key.pem: %v", err)
	}

	// The generated pair must actually work for wrap/unwrap.
	w, err := certkey.WrapSecret([]byte("hunter2-plenty-long"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	got, err := certkey.UnwrapSecret(w, keyPEM)
	if err != nil {
		t.Fatalf("UnwrapSecret: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestRun_CertGenDoesNotRequireVaultFlag(t *testing.T) {
	// cert-gen touches no vault at all, so it must work identically to
	// "vaults"/"assets" with no -vault flag and no vault.*.json on disk.
	app, _, stderr := newTestApp(t)
	outDir := filepath.Join(t.TempDir(), "certs")
	if code := app.Run([]string{"cert-gen", outDir}); code != 0 {
		t.Fatalf("cert-gen: code=%d stderr=%s", code, stderr.String())
	}
}

func TestRun_CertWrapThenNonInteractiveExtract(t *testing.T) {
	certPEM, keyPEM := genRSACert(t)

	app, stdout, stderr := newTestApp(t,
		"correct-secret", // inject: sets the vault secret
		"correct-secret", // cert-wrap: current secret
	)

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	wrappedPath := filepath.Join(dir, "wrapped.json")
	if code := app.Run([]string{"-vault", "dev", "cert-wrap", certPath, wrappedPath}); code != 0 {
		t.Fatalf("cert-wrap: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wrapped") {
		t.Errorf("stdout after cert-wrap = %q", stdout.String())
	}
	if _, err := os.Stat(wrappedPath); err != nil {
		t.Fatalf("wrapped secret file missing: %v", err)
	}

	// Simulate the non-interactive side: a second App, using the same
	// vault.Store.Dir but a certkey.Prompter instead of a human — no
	// secrets queued at all, proving no human interaction happens.
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	var nonInteractiveStdout, nonInteractiveStderr bytes.Buffer
	nonInteractiveApp := &App{
		Store:    app.Store,
		Prompter: certkey.Prompter{WrappedFile: wrappedPath, KeyFile: keyPath},
		Stdout:   &nonInteractiveStdout,
		Stderr:   &nonInteractiveStderr,
	}
	dest := filepath.Join(t.TempDir(), "out.txt")
	if code := nonInteractiveApp.Run([]string{"-vault", "dev", "extract", "note", dest}); code != 0 {
		t.Fatalf("non-interactive extract: code=%d stderr=%s", code, nonInteractiveStderr.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("extracted content = %q, %v", got, err)
	}
}

func TestRun_CertWrapEmptyVaultRejected(t *testing.T) {
	certPEM, _ := genRSACert(t)
	app, _, stderr := newTestApp(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	wrappedPath := filepath.Join(dir, "wrapped.json")
	if code := app.Run([]string{"-vault", "dev", "cert-wrap", certPath, wrappedPath}); code == 0 {
		t.Fatal("cert-wrap on an empty vault unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "empty") {
		t.Errorf("stderr = %q, want mention of the empty vault", stderr.String())
	}
}

func TestRun_CertWrapWrongSecretRejected(t *testing.T) {
	certPEM, _ := genRSACert(t)
	app, _, stderr := newTestApp(t, "correct-secret", "wrong-secret!")

	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if code := app.Run([]string{"-vault", "dev", "inject", "note", src}); code != 0 {
		t.Fatalf("inject: code=%d", code)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	wrappedPath := filepath.Join(dir, "wrapped.json")
	if code := app.Run([]string{"-vault", "dev", "cert-wrap", certPath, wrappedPath}); code == 0 {
		t.Fatal("cert-wrap with the wrong current secret unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "secret does not match") {
		t.Errorf("stderr = %q, want mention of a non-matching secret", stderr.String())
	}
	if _, err := os.Stat(wrappedPath); err == nil {
		t.Fatal("wrapped secret file was written despite the wrong secret")
	}
}

// TestRun_FullNonInteractiveWorkflow walks the complete story end to end:
// generate a self-signed cert/key pair, bundle the pair itself into its own
// password-protected "key vault" (so the private key is never a bare
// plaintext file at rest or in transit), populate a separate "data" vault
// with a real secret, wrap the data vault's secret to the certificate, then
// simulate arriving on a server: a one-time interactive step recovers the
// key vault's contents to disk, after which the data vault is extracted
// with zero secrets typed — proving the automation path needs a human only
// once, for provisioning, never for the actual application run.
func TestRun_FullNonInteractiveWorkflow(t *testing.T) {
	app, stdout, stderr := newTestApp(t,
		"keyvault-secret-long-enough", // inject -dir into "keyvault": sets its secret
		"prod-secret-long-enough",     // inject into "prod": sets its secret
		"prod-secret-long-enough",     // cert-wrap "prod": verifies current secret
		"keyvault-secret-long-enough", // extract -dir "keyvault" on the "server": one-time recovery
	)
	root := t.TempDir()

	// 1. Generate a self-signed RSA cert/key pair. No vault, no secret.
	certsDir := filepath.Join(root, "certs")
	if code := app.Run([]string{"cert-gen", certsDir}); code != 0 {
		t.Fatalf("cert-gen: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cert.pem") {
		t.Errorf("stdout after cert-gen = %q", stdout.String())
	}
	stdout.Reset()

	// 2. Bundle the cert+key pair itself into its own vault, protected by a
	// password — this is what actually gets "deployed to the server": a
	// single encrypted file, not bare key material.
	if code := app.Run([]string{"-vault", "keyvault", "inject", "-dir", certsDir}); code != 0 {
		t.Fatalf("inject keyvault: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// 3. Populate the real "prod" data vault with an application secret.
	dbSecretSrc := filepath.Join(root, "db-password.txt")
	if err := os.WriteFile(dbSecretSrc, []byte("hunter2"), 0o600); err != nil {
		t.Fatalf("write db secret source: %v", err)
	}
	if code := app.Run([]string{"-vault", "prod", "inject", "db-password", dbSecretSrc}); code != 0 {
		t.Fatalf("inject prod: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// 4. Wrap prod's secret to the certificate's public key — this is the
	// step that would be run once, wherever prod's secret is known, and the
	// resulting file shipped alongside vault.prod.json.
	wrappedPath := filepath.Join(root, "prod.wrapped.json")
	if code := app.Run([]string{"-vault", "prod", "cert-wrap", filepath.Join(certsDir, "cert.pem"), wrappedPath}); code != 0 {
		t.Fatalf("cert-wrap: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()

	// 5. Simulate arriving on the server: everything above (vault.keyvault.json,
	// vault.prod.json, prod.wrapped.json — all just files under app.Store.Dir)
	// is now "deployed". A one-time interactive step recovers the private
	// key from the key vault onto local disk.
	recoveredDir := filepath.Join(root, "recovered")
	if err := os.MkdirAll(recoveredDir, 0o755); err != nil {
		t.Fatalf("mkdir recoveredDir: %v", err)
	}
	if code := app.Run([]string{"-vault", "keyvault", "extract", "-dir", recoveredDir}); code != 0 {
		t.Fatalf("extract keyvault: code=%d stderr=%s", code, stderr.String())
	}
	// injectDir prefixed entry names with certsDir's own base name, so
	// extract -dir recreates that same layout under recoveredDir.
	recoveredKeyPath := filepath.Join(recoveredDir, filepath.Base(certsDir), "key.pem")
	if _, err := os.Stat(recoveredKeyPath); err != nil {
		t.Fatalf("recovered private key missing: %v", err)
	}

	// 6. The actual non-interactive run: a fresh App wired with
	// certkey.Prompter instead of a human, and NO secrets queued at all.
	var nonInteractiveStdout, nonInteractiveStderr bytes.Buffer
	nonInteractiveApp := &App{
		Store:    app.Store,
		Prompter: certkey.Prompter{WrappedFile: wrappedPath, KeyFile: recoveredKeyPath},
		Stdout:   &nonInteractiveStdout,
		Stderr:   &nonInteractiveStderr,
	}
	dest := filepath.Join(root, "restored-db-password.txt")
	if code := nonInteractiveApp.Run([]string{"-vault", "prod", "extract", "db-password", dest}); code != 0 {
		t.Fatalf("non-interactive extract: code=%d stderr=%s", code, nonInteractiveStderr.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("restored secret = %q, %v, want %q", got, err, "hunter2")
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
