// Package certkey lets a vault's secret be recovered without a human typing
// it, by wrapping (envelope-encrypting) that secret to an RSA certificate's
// public key ahead of time and unwrapping it later with the matching
// private key. This exists for non-interactive contexts — CI, cron, deploy
// scripts — where internal/terminal's Prompter cannot work at all, since
// term.ReadPassword requires a real controlling terminal.
//
// WrapSecret does not encrypt the vault secret directly with RSA: RSA-OAEP
// has a plaintext-size ceiling set by the key's modulus (e.g. ~190 bytes for
// a 2048-bit key with SHA-256 OAEP), which a passphrase could exceed. So a
// fresh random AES-256 data key is generated for every wrap, the secret is
// sealed under that data key with AES-256-GCM, and only the small,
// fixed-size data key is wrapped with RSA-OAEP — the same envelope-
// encryption pattern used by, e.g., cloud KMS "encrypt with a data key"
// APIs. This means secret length is never limited by the certificate's key
// size.
package certkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// aad binds the AES-GCM ciphertext to this format so it can never be
// mistaken for ciphertext from a different scheme (mirrors vault.aad's
// domain-separation role) and doubles as a format version marker.
var aad = []byte("boxcar-cert-wrapped-secret-v1")

const dataKeyLen = 32 // AES-256

// WrappedSecret is the on-disk envelope produced by WrapSecret: a random
// AES-256 data key wrapped with RSA-OAEP under the certificate's public
// key, and the actual secret sealed under that data key with AES-256-GCM.
type WrappedSecret struct {
	WrappedKey []byte `json:"wrappedKey"` // RSA-OAEP(SHA-256) ciphertext of the data key
	Nonce      []byte `json:"nonce"`      // AES-GCM nonce
	Ciphertext []byte `json:"ciphertext"` // AES-GCM(secret) under the data key
}

// WrapSecret encrypts secret so it can only be recovered by UnwrapSecret
// with the private key matching certPEM's public key. certPEM must be a
// PEM-encoded X.509 certificate whose public key is RSA — no other key
// algorithm is currently supported.
func WrapSecret(secret, certPEM []byte) (*WrappedSecret, error) {
	pub, err := parseCertPublicKey(certPEM)
	if err != nil {
		return nil, err
	}

	dataKey := make([]byte, dataKeyLen)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	defer vault.Zero(dataKey)

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dataKey, nil)
	if err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, secret, aad)

	return &WrappedSecret{
		WrappedKey: wrappedKey,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// UnwrapSecret recovers the secret WrapSecret sealed into w, using the
// PEM-encoded RSA private key keyPEM (PKCS#1 "RSA PRIVATE KEY" or PKCS#8
// "PRIVATE KEY"). It fails if keyPEM doesn't match the certificate WrapSecret
// used, or if w was tampered with.
func UnwrapSecret(w *WrappedSecret, keyPEM []byte) ([]byte, error) {
	priv, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, w.WrappedKey, nil)
	if err != nil {
		return nil, errors.New("incorrect private key or corrupted wrapped secret")
	}
	defer vault.Zero(dataKey)

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	secret, err := gcm.Open(nil, w.Nonce, w.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("incorrect private key or corrupted wrapped secret")
	}
	return secret, nil
}

// Save writes w as JSON to path with 0600 permissions — it holds an
// RSA-wrapped secret, not the secret itself, but is still treated as
// sensitive: possession of it plus the matching private key is enough to
// recover the vault's secret.
func (w *WrappedSecret) Save(path string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Load reads a WrappedSecret previously written by WrappedSecret.Save.
func Load(path string) (*WrappedSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w WrappedSecret
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func parseCertPublicKey(certPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM data found in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate's public key is %T, only RSA is currently supported", cert.PublicKey)
	}
	return pub, nil
}

func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM data found in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key (tried PKCS#1 and PKCS#8): %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, only RSA is currently supported", key)
	}
	return rsaKey, nil
}
