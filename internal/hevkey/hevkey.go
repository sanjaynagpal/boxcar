// Package hevkey lets a vault's secret be recovered without any human ever
// knowing it, by holding the secret in HashiCorp Enterprise Vault (HEV) and
// having boxcar authenticate to HEV itself with an mTLS client certificate
// at run time. This exists for the "non-person technical account" scenario:
// a shared/service-account boxcar vault whose secret is generated and
// custodied entirely inside HEV, fetched fresh on every command instead of
// being typed by, or wrapped for, a person (contrast internal/certkey, which
// still requires a human to supply the secret once via cert-wrap).
//
// FetchSecret performs two calls against HEV's HTTP API: it logs in via the
// "cert" auth method (the TLS handshake itself presents the client
// certificate; HEV matches it against its configured trusted CAs/role) to
// obtain a short-lived token, then reads a single KV secret at a configured
// path using that token. Only the HTTP calls HEV's own API demands are
// implemented here, by hand, with net/http and crypto/tls — no HashiCorp SDK
// dependency, consistent with how internal/certkey hand-implements its own
// RSA/AES-GCM envelope rather than depending on a crypto library.
package hevkey

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// defaultSecretField is used when Config.SecretField is empty.
const defaultSecretField = "secret"

// httpTimeout bounds both the login and secret-read requests so a
// misbehaving or unreachable HEV endpoint fails fast rather than hanging a
// boxcar command indefinitely.
const httpTimeout = 15 * time.Second

// Config holds everything needed to authenticate to HEV via mTLS and read
// the one secret a boxcar vault needs. All fields are read from PEM/text
// bytes rather than file paths so callers (e.g. cmd/boxcar) own file I/O and
// env var parsing; this package only knows how to talk to HEV.
type Config struct {
	// Addr is HEV's base URL, e.g. "https://vault.example.com:8200".
	Addr string
	// ClientCertPEM/ClientKeyPEM are the PEM-encoded mTLS client
	// certificate and matching private key presented during the TLS
	// handshake, and authenticated by HEV's "cert" auth method.
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	// CACertPEM, if set, is a PEM CA bundle used to verify HEV's server
	// certificate. If empty, the system trust store is used instead.
	CACertPEM []byte
	// SecretPath is the HEV path to read, e.g. "secret/data/boxcar/prod"
	// (KV v2) or "secret/boxcar/prod" (KV v1) — the single path used for
	// every operation against one boxcar vault.
	SecretPath string
	// SecretField is the field name within the KV secret's data map that
	// holds the boxcar vault secret. Defaults to "secret" if empty.
	SecretField string
	// AuthRole, if set, is passed as "name" in the cert auth login body,
	// selecting a specific HEV "cert" auth role. Optional: omit if HEV is
	// configured with a single/default role for this certificate.
	AuthRole string
	// Namespace, if set, is sent as the X-Vault-Namespace header on every
	// request (HEV/Vault Enterprise namespaces).
	Namespace string
}

type loginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

// FetchSecret authenticates to HEV per cfg and returns the secret stored at
// cfg.SecretPath/cfg.SecretField. Every returned error is safe to print: it
// never includes the secret itself.
func FetchSecret(cfg Config) ([]byte, error) {
	client, err := newHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure HEV TLS client: %w", err)
	}

	token, err := certLogin(client, cfg)
	if err != nil {
		return nil, fmt.Errorf("HEV cert login: %w", err)
	}

	secret, err := readSecret(client, cfg, token)
	if err != nil {
		return nil, fmt.Errorf("read HEV secret at %q: %w", cfg.SecretPath, err)
	}

	if err := vault.CheckSecretLength(secret); err != nil {
		vault.Zero(secret)
		return nil, err
	}
	return secret, nil
}

func newHTTPClient(cfg Config) (*http.Client, error) {
	cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate/key: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, fmt.Errorf("no certificates found in CA bundle")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   httpTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func certLogin(client *http.Client, cfg Config) (string, error) {
	body := map[string]string{}
	if cfg.AuthRole != "" {
		body["name"] = cfg.AuthRole
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.Addr, "/")+"/v1/auth/cert/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", cfg.Namespace)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, data)
	}

	var lr loginResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("parse login response: %w", err)
	}
	if lr.Auth.ClientToken == "" {
		return "", fmt.Errorf("login response contained no client token")
	}
	return lr.Auth.ClientToken, nil
}

func readSecret(client *http.Client, cfg Config, token string) ([]byte, error) {
	path := strings.TrimLeft(cfg.SecretPath, "/")
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.Addr, "/")+"/v1/"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", cfg.Namespace)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, data)
	}

	var body struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("parse secret response: %w", err)
	}

	// KV v2 nests the actual field map under an inner "data" key; KV v1
	// puts fields directly under the top-level "data" key. Try v2 first,
	// falling back to v1 if there's no nested "data" object.
	var v2 struct {
		Data map[string]any `json:"data"`
	}
	fields := map[string]any{}
	if err := json.Unmarshal(body.Data, &v2); err == nil && v2.Data != nil {
		fields = v2.Data
	} else if err := json.Unmarshal(body.Data, &fields); err != nil {
		return nil, fmt.Errorf("parse secret data: %w", err)
	}

	field := cfg.SecretField
	if field == "" {
		field = defaultSecretField
	}
	raw, ok := fields[field]
	if !ok {
		return nil, fmt.Errorf("secret has no field %q", field)
	}
	str, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("field %q is not a string", field)
	}
	return []byte(str), nil
}
