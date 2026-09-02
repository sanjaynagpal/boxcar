package hevkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// genCA returns a fresh self-signed CA cert (PEM + parsed form) and its
// private key, used to sign both the fake HEV server's cert and the client
// certs presented to it in tests.
func genCA(t *testing.T) (certPEM []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, priv
}

// issueCert signs a leaf cert (server or client) with the given CA, returning
// its PEM cert and key.
func issueCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// newTestHEV starts a fake HEV server requiring a valid client cert signed
// by caCert, and returns a Config pre-populated with a valid client
// cert/key and CA so tests only need to set SecretPath/SecretField/etc.
func newTestHEV(t *testing.T, handler http.HandlerFunc) (Config, *httptest.Server) {
	t.Helper()
	caCertPEM, caCert, caKey := genCA(t)
	serverCertPEM, serverKeyPEM := issueCert(t, caCert, caKey, "hev-test-server", true)
	clientCertPEM, clientKeyPEM := issueCert(t, caCert, caKey, "boxcar-test-client", false)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (server): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return Config{
		Addr:          srv.URL,
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		CACertPEM:     caCertPEM,
	}, srv
}

func loginOKHandler(t *testing.T, wantRole string, token string) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/v1/auth/cert/login" {
			return false
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode login body: %v", err)
		}
		if wantRole != "" && body["name"] != wantRole {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"errors":["role mismatch"]}`)
			return true
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"auth":{"client_token":%q}}`, token)
		return true
	}
}

func TestFetchSecret_KVv2(t *testing.T) {
	const token = "test-token"
	login := loginOKHandler(t, "", token)
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		if r.URL.Path != "/v1/secret/data/boxcar/prod" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != token {
			t.Fatalf("X-Vault-Token = %q, want %q", got, token)
		}
		fmt.Fprint(w, `{"data":{"data":{"secret":"hunter2-plenty-long"},"metadata":{}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	got, err := FetchSecret(cfg)
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestFetchSecret_KVv1(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		fmt.Fprint(w, `{"data":{"secret":"hunter2-plenty-long"}}`)
	})
	cfg.SecretPath = "secret/boxcar/prod"

	got, err := FetchSecret(cfg)
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestFetchSecret_CustomField(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"password":"hunter2-plenty-long"}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"
	cfg.SecretField = "password"

	got, err := FetchSecret(cfg)
	if err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}

func TestFetchSecret_MissingFieldRejected(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"other":"value"}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	if _, err := FetchSecret(cfg); err == nil {
		t.Fatal("FetchSecret succeeded with no matching secret field")
	}
}

func TestFetchSecret_TooShortSecretRejected(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"secret":"abc"}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	if _, err := FetchSecret(cfg); err == nil {
		t.Fatal("FetchSecret succeeded with a too-short secret")
	}
}

func TestFetchSecret_AuthRoleMismatchRejected(t *testing.T) {
	login := loginOKHandler(t, "expected-role", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		login(w, r)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"
	cfg.AuthRole = "wrong-role"

	if _, err := FetchSecret(cfg); err == nil {
		t.Fatal("FetchSecret succeeded despite a role mismatch")
	}
}

func TestFetchSecret_NamespaceHeaderSent(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	var gotLoginNS, gotReadNS string
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/cert/login" {
			gotLoginNS = r.Header.Get("X-Vault-Namespace")
			login(w, r)
			return
		}
		gotReadNS = r.Header.Get("X-Vault-Namespace")
		fmt.Fprint(w, `{"data":{"data":{"secret":"hunter2-plenty-long"}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"
	cfg.Namespace = "team-a"

	if _, err := FetchSecret(cfg); err != nil {
		t.Fatalf("FetchSecret: %v", err)
	}
	if gotLoginNS != "team-a" {
		t.Fatalf("login namespace header = %q, want %q", gotLoginNS, "team-a")
	}
	if gotReadNS != "team-a" {
		t.Fatalf("read namespace header = %q, want %q", gotReadNS, "team-a")
	}
}

func TestFetchSecret_WrongClientCertRejectedByTLS(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		login(w, r)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	// A cert signed by an unrelated CA must be rejected at the TLS layer
	// before any HTTP request is even processed.
	otherCACertPEM, otherCACert, otherCAKey := genCA(t)
	_ = otherCACertPEM
	badCertPEM, badKeyPEM := issueCert(t, otherCACert, otherCAKey, "untrusted-client", false)
	cfg.ClientCertPEM = badCertPEM
	cfg.ClientKeyPEM = badKeyPEM

	if _, err := FetchSecret(cfg); err == nil {
		t.Fatal("FetchSecret succeeded with a client cert from an untrusted CA")
	}
}

func TestFetchSecret_LoginFailureRejected(t *testing.T) {
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":["permission denied"]}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	if _, err := FetchSecret(cfg); err == nil {
		t.Fatal("FetchSecret succeeded despite a login failure")
	}
}

func TestPrompter_Prompt(t *testing.T) {
	login := loginOKHandler(t, "", "tok")
	cfg, _ := newTestHEV(t, func(w http.ResponseWriter, r *http.Request) {
		if login(w, r) {
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"secret":"hunter2-plenty-long"}}}`)
	})
	cfg.SecretPath = "secret/data/boxcar/prod"

	p := Prompter{Config: cfg}
	got, err := p.Prompt("ignored prompt text", true /* also ignored */)
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if string(got) != "hunter2-plenty-long" {
		t.Fatalf("got %q, want %q", got, "hunter2-plenty-long")
	}
}
