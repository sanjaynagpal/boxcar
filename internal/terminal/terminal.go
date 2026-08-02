// Package terminal reads secrets from the controlling terminal with echo
// disabled.
package terminal

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/term"

	"github.com/sanjaynagpal/boxcar/internal/vault"
)

// Prompter reads secrets from a terminal file descriptor, echoing a prompt
// to Out but never the input itself.
type Prompter struct {
	// Out receives prompt text (typically os.Stderr).
	Out io.Writer
	// FD is the file descriptor to read from (typically int(os.Stdin.Fd())).
	FD int
}

// Prompt reads a secret, enforcing vault.MinSecretLen. When confirm is true
// it is read a second time and the two must match.
//
// On success, the caller owns the returned secret and is responsible for
// zeroing it (vault.Zero) once done with it. Every buffer Prompt itself
// discards along the way — a mismatched confirmation, an over-short first
// read — is zeroed before Prompt returns.
func (p Prompter) Prompt(prompt string, confirm bool) ([]byte, error) {
	fmt.Fprint(p.Out, prompt)
	s1, err := term.ReadPassword(p.FD)
	fmt.Fprintln(p.Out)
	if err != nil {
		return nil, err
	}
	if err := vault.CheckSecretLength(s1); err != nil {
		vault.Zero(s1)
		return nil, err
	}
	// Only nag when a new secret is being chosen (confirm==true) — by the
	// time a secret is just being re-entered to unlock an existing vault or
	// extract an entry, warning about its strength can't change anything.
	if confirm && vault.IsWeakSecret(s1) {
		fmt.Fprintf(p.Out, "warning: this secret is short or commonly used; consider a longer, unique passphrase (%d+ characters recommended)\n", vault.RecommendedSecretLen)
	}
	if confirm {
		fmt.Fprint(p.Out, "Confirm secret: ")
		s2, err := term.ReadPassword(p.FD)
		fmt.Fprintln(p.Out)
		if err != nil {
			vault.Zero(s1)
			return nil, err
		}
		match := subtle.ConstantTimeCompare(s1, s2) == 1
		vault.Zero(s2)
		if !match {
			vault.Zero(s1)
			return nil, errors.New("secrets do not match")
		}
	}
	return s1, nil
}
