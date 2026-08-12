package certkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genRSACert returns a self-signed RSA cert/key pair PEM-encoded via
// GenerateSelfSigned itself, plus the parsed private key for tests that
// need to re-encode it (e.g. as PKCS#8) — so cert-generation logic isn't
// duplicated between production code and tests.
func genRSACert(t *testing.T) (certPEM, keyPEM []byte, priv *rsa.PrivateKey) {
	t.Helper()
	certPEM, keyPEM, err := GenerateSelfSigned("test")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	priv, err = parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	return certPEM, keyPEM, priv
}

// selfSignCert builds a self-signed cert for an arbitrary key type (e.g.
// ECDSA), for tests that specifically need a non-RSA certificate —
// GenerateSelfSigned only ever produces RSA.
func selfSignCert(t *testing.T, pub, signerPriv any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signerPriv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	certPEM, keyPEM, _ := genRSACert(t)

	secret := []byte("correct-horse-battery-staple")
	w, err := WrapSecret(secret, certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	got, err := UnwrapSecret(w, keyPEM)
	if err != nil {
		t.Fatalf("UnwrapSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("UnwrapSecret = %q, want %q", got, secret)
	}
}

func TestWrapUnwrapRoundTrip_LongSecret(t *testing.T) {
	// Longer than RSA-2048/SHA-256 OAEP's ~190-byte direct-encryption
	// ceiling — proves the envelope (data key) design doesn't inherit RSA's
	// plaintext-size limit.
	certPEM, keyPEM, _ := genRSACert(t)
	secret := make([]byte, 4096)
	for i := range secret {
		secret[i] = byte('a' + i%26)
	}

	w, err := WrapSecret(secret, certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	got, err := UnwrapSecret(w, keyPEM)
	if err != nil {
		t.Fatalf("UnwrapSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatal("long secret did not round-trip correctly")
	}
}

func TestUnwrapSecret_WrongKeyRejected(t *testing.T) {
	certPEM, _, _ := genRSACert(t)
	_, otherKeyPEM, _ := genRSACert(t)

	w, err := WrapSecret([]byte("hunter2"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	if _, err := UnwrapSecret(w, otherKeyPEM); err == nil {
		t.Fatal("UnwrapSecret succeeded with a non-matching private key")
	}
}

func TestUnwrapSecret_TamperedCiphertextRejected(t *testing.T) {
	certPEM, keyPEM, _ := genRSACert(t)
	w, err := WrapSecret([]byte("hunter2"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	w.Ciphertext[0] ^= 0xFF
	if _, err := UnwrapSecret(w, keyPEM); err == nil {
		t.Fatal("UnwrapSecret succeeded on tampered ciphertext")
	}
}

func TestWrapSecret_NonRSACertRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM := selfSignCert(t, &priv.PublicKey, priv)

	if _, err := WrapSecret([]byte("hunter2"), certPEM); err == nil {
		t.Fatal("WrapSecret succeeded against a non-RSA certificate")
	}
}

func TestUnwrapSecret_NonRSAKeyRejected(t *testing.T) {
	certPEM, _, _ := genRSACert(t)
	w, err := WrapSecret([]byte("hunter2"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	ecKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, err := UnwrapSecret(w, ecKeyPEM); err == nil {
		t.Fatal("UnwrapSecret succeeded with a non-RSA private key")
	}
}

func TestParsePrivateKey_PKCS1AndPKCS8(t *testing.T) {
	certPEM, pkcs1PEM, priv := genRSACert(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	w, err := WrapSecret([]byte("hunter2"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	for name, keyPEM := range map[string][]byte{"PKCS1": pkcs1PEM, "PKCS8": pkcs8PEM} {
		t.Run(name, func(t *testing.T) {
			got, err := UnwrapSecret(w, keyPEM)
			if err != nil {
				t.Fatalf("UnwrapSecret: %v", err)
			}
			if string(got) != "hunter2" {
				t.Fatalf("got %q, want %q", got, "hunter2")
			}
		})
	}
}

func TestWrappedSecret_SaveLoadRoundTrip(t *testing.T) {
	certPEM, keyPEM, _ := genRSACert(t)
	w, err := WrapSecret([]byte("hunter2"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}

	path := filepath.Join(t.TempDir(), "wrapped.json")
	if err := w.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := UnwrapSecret(loaded, keyPEM)
	if err != nil {
		t.Fatalf("UnwrapSecret after Save/Load: %v", err)
	}
	if string(got) != "hunter2" {
		t.Fatalf("got %q, want %q", got, "hunter2")
	}
}

func TestPrompter_Prompt(t *testing.T) {
	certPEM, keyPEM, _ := genRSACert(t)
	w, err := WrapSecret([]byte("hunter2-plenty-long"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}

	dir := t.TempDir()
	wrappedPath := filepath.Join(dir, "wrapped.json")
	keyPath := filepath.Join(dir, "key.pem")
	if err := w.Save(wrappedPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	p := Prompter{WrappedFile: wrappedPath, KeyFile: keyPath}
	got, err := p.Prompt("ignored prompt text", true /* also ignored */)
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestPrompter_Prompt_TooShortSecretRejected(t *testing.T) {
	certPEM, keyPEM, _ := genRSACert(t)
	w, err := WrapSecret([]byte("abc"), certPEM) // shorter than vault.MinSecretLen
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}

	dir := t.TempDir()
	wrappedPath := filepath.Join(dir, "wrapped.json")
	keyPath := filepath.Join(dir, "key.pem")
	if err := w.Save(wrappedPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	p := Prompter{WrappedFile: wrappedPath, KeyFile: keyPath}
	if _, err := p.Prompt("prompt", false); err == nil {
		t.Fatal("Prompt succeeded with a too-short unwrapped secret")
	}
}

func TestPrompter_Prompt_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	p := Prompter{
		WrappedFile: filepath.Join(dir, "does-not-exist.json"),
		KeyFile:     filepath.Join(dir, "does-not-exist.pem"),
	}
	if _, err := p.Prompt("prompt", false); err == nil {
		t.Fatal("Prompt succeeded with a missing wrapped-secret file")
	}
}

func TestGenerateSelfSigned_ProducesUsableCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSigned("boxcar-test")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	// The generated pair must actually work with Wrap/UnwrapSecret — that's
	// its entire purpose.
	w, err := WrapSecret([]byte("hunter2-plenty-long"), certPEM)
	if err != nil {
		t.Fatalf("WrapSecret: %v", err)
	}
	got, err := UnwrapSecret(w, keyPEM)
	if err != nil {
		t.Fatalf("UnwrapSecret: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestGenerateSelfSigned_DistinctKeysPerCall(t *testing.T) {
	_, keyPEM1, err := GenerateSelfSigned("a")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	_, keyPEM2, err := GenerateSelfSigned("b")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if string(keyPEM1) == string(keyPEM2) {
		t.Fatal("two calls to GenerateSelfSigned produced identical keys")
	}
}

func TestGenerateSelfSigned_CertParsesAsX509(t *testing.T) {
	certPEM, _, err := GenerateSelfSigned("boxcar-test")
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected a CERTIFICATE PEM block, got %+v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "boxcar-test" {
		t.Fatalf("CommonName = %q, want %q", cert.Subject.CommonName, "boxcar-test")
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", cert.PublicKey)
	}
}
