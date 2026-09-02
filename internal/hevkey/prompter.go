package hevkey

// Prompter fetches a vault secret from HEV on every call, with no human
// interaction — it implements the same interface as terminal.Prompter
// (Prompt(prompt string, confirm bool) ([]byte, error)) via structural
// typing, so cli.App can use it interchangeably with terminal.Prompter or
// certkey.Prompter. Both prompt and confirm are ignored: there's no
// interactive text to display, and correctness comes from HEV's own cert
// auth and KV read, not from a second entry to compare against.
type Prompter struct {
	Config Config
}

func (p Prompter) Prompt(prompt string, confirm bool) ([]byte, error) {
	return FetchSecret(p.Config)
}
