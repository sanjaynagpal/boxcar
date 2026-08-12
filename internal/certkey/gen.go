package certkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// selfSignedBits is the RSA key size GenerateSelfSigned uses. Fixed rather
// than configurable: 2048 bits is the de facto minimum for RSA-OAEP today,
// comfortably wraps a 32-byte AES data key (see WrapSecret), and matches
// what "RSA only" already assumes elsewhere in this package.
const selfSignedBits = 2048

// selfSignedValidity is set generously (10 years) because this certificate
// is never used for TLS/trust-chain validation — parseCertPublicKey only
// ever reads its public key out — so an "expired" self-signed cert would
// still wrap/unwrap correctly. The long validity just avoids the
// certificate becoming a red flag in tooling that does check dates.
const selfSignedValidity = 10 * 365 * 24 * time.Hour

// GenerateSelfSigned creates a fresh RSA key pair and a self-signed X.509
// certificate for it, both PEM-encoded, for use with WrapSecret/UnwrapSecret.
// commonName is cosmetic only (it's never validated against anything); it
// exists so the certificate identifies what it's for when inspected with
// standard tools (e.g. `openssl x509 -text`).
func GenerateSelfSigned(commonName string) (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, selfSignedBits)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour), // small clock-skew allowance
		NotAfter:              time.Now().Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}
