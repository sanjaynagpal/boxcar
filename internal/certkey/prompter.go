package certkey

import (
	"fmt"
	"os"

	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// Prompter recovers a vault secret from a pre-wrapped file and a local
// private key, with no human interaction — it implements the same
// interface as terminal.Prompter (Prompt(prompt string, confirm bool)
// ([]byte, error)) via structural typing, so cli.App can use either
// interchangeably. Both prompt and confirm are ignored: there's no
// interactive text to display, and there's no second entry to compare
// against — correctness is enforced by RSA-OAEP/AES-GCM authentication in
// UnwrapSecret, the same way vault entries themselves are never checked by
// string comparison.
type Prompter struct {
	// WrappedFile is the path to a WrappedSecret JSON file previously
	// produced by `boxcar cert-wrap` (via WrappedSecret.Save).
	WrappedFile string
	// KeyFile is the path to a PEM-encoded RSA private key matching the
	// certificate WrapSecret was called with.
	KeyFile string
}

func (p Prompter) Prompt(prompt string, confirm bool) ([]byte, error) {
	w, err := Load(p.WrappedFile)
	if err != nil {
		return nil, fmt.Errorf("read wrapped secret %q: %w", p.WrappedFile, err)
	}
	keyPEM, err := os.ReadFile(p.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", p.KeyFile, err)
	}

	secret, err := UnwrapSecret(w, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := vault.CheckSecretLength(secret); err != nil {
		vault.Zero(secret)
		return nil, err
	}
	return secret, nil
}
