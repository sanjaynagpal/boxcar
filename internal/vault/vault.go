// Package vault implements a runtime-mutable, secret-protected store.
//
// Every entry is sealed with AES-256-GCM using a key derived (via scrypt)
// from a per-entry random salt. Because AES-GCM authentication fails when
// the wrong key is used, secret correctness is enforced cryptographically —
// there is no separate stored password hash to compare against. Each
// entry's additional authenticated data binds the ciphertext to both its
// vault name and entry name, so an entry cannot be decrypted after being
// moved to a different vault or renamed.
//
// A Store persists vaults as sidecar JSON files (vault.<NAME>.json) on disk,
// separate from any compile-time embedded assets, which Go's embed.FS
// cannot hold since it is read-only and fixed at build time.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// scrypt parameters (interactive-login strength).
const (
	scryptN = 1 << 15 // 32768
	scryptR = 8
	scryptP = 1
	keyLen  = 32 // AES-256

	saltLen = 16

	// MinSecretLen is the minimum accepted secret length. It's a hard
	// floor enforced by CheckSecretLength — mainly to catch typos — not a
	// strength guarantee. See RecommendedSecretLen for advisory guidance.
	MinSecretLen = 6

	// RecommendedSecretLen is the length at or above which IsWeakSecret no
	// longer flags a secret as weak on length alone. It's advisory only:
	// nothing enforces it.
	RecommendedSecretLen = 16
)

// commonWeakSecrets are values trivially guessable regardless of length —
// found at or near the top of nearly every leaked-password frequency list.
var commonWeakSecrets = []string{
	"password", "password1", "123456", "12345678", "123456789",
	"qwerty", "letmein", "111111", "000000", "abc123",
	"iloveyou", "admin", "welcome", "monkey", "dragon",
}

// IsWeakSecret reports whether secret is short of RecommendedSecretLen or is
// one of a small set of commonly used, trivially guessable values. It is
// advisory only — CheckSecretLength is the hard-enforced rule; callers may
// use IsWeakSecret to warn a user without blocking them.
func IsWeakSecret(secret []byte) bool {
	if len(secret) < RecommendedSecretLen {
		return true
	}
	for _, weak := range commonWeakSecrets {
		if bytes.EqualFold(secret, []byte(weak)) {
			return true
		}
	}
	return false
}

// ValidNamePattern is the allowed shape of a vault name: a safe filename
// component with no path separators, "..", or spaces.
var ValidNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// IsValidName reports whether name is a safe vault name.
func IsValidName(name string) bool { return ValidNamePattern.MatchString(name) }

// CheckSecretLength returns an error if secret is shorter than MinSecretLen.
func CheckSecretLength(secret []byte) error {
	if len(secret) < MinSecretLen {
		return fmt.Errorf("secret must be at least %d characters", MinSecretLen)
	}
	return nil
}

// Zero overwrites b with zero bytes in place. Callers should zero a secret
// (or a key derived from one) as soon as it's no longer needed, so it
// doesn't linger in memory — e.g. in a core dump or a page swapped to disk —
// for longer than necessary. This is defense-in-depth, not a guarantee: Go's
// runtime can leave other copies behind (from string conversions, escape
// analysis, GC moves) that this function has no access to.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Entry is one injected, encrypted file.
type Entry struct {
	Name       string `json:"name"`
	Salt       []byte `json:"salt"`       // per-entry KDF salt
	Nonce      []byte `json:"nonce"`      // per-entry GCM nonce
	Ciphertext []byte `json:"ciphertext"` // AES-GCM sealed bytes (includes auth tag)

	// OrigName is the base name (filepath.Base) of the source file at the
	// time it was injected, e.g. "password.txt" for a file injected as
	// `inject db-password ./secrets/password.txt`. It's recorded purely so
	// a later `extract <name> <destFolder>` can recreate that exact file
	// name inside destFolder without the caller having to remember or
	// retype it; it plays no role in encryption (not part of the AEAD
	// additional data, unlike Name) and, like Name, is stored as plaintext
	// metadata in vault.<NAME>.json. Empty for entries where no source file
	// name was recorded (e.g. sealed directly via the vault package, or
	// written before this field existed).
	OrigName string `json:"origName,omitempty"`

	// ScryptN, ScryptR, ScryptP are the scrypt cost parameters this entry
	// was actually sealed with. SealEntry always records the package's
	// current scryptN/R/P consts here. Entries written before this field
	// existed have it unset (zero) once unmarshaled; scryptParams treats
	// zero as "use the current package consts", so old vault.*.json files
	// keep decrypting correctly even after those consts are later raised —
	// a future cost bump only affects newly sealed entries, never breaks
	// entries sealed under the old cost.
	ScryptN int `json:"scryptN,omitempty"`
	ScryptR int `json:"scryptR,omitempty"`
	ScryptP int `json:"scryptP,omitempty"`
}

// scryptParams returns the cost parameters to use when deriving a key for
// e, falling back to the package's current defaults for any zero (unset)
// field — which is exactly the shape of an entry unmarshaled from a
// vault.*.json written before per-entry params existed.
func (e Entry) scryptParams() (n, r, p int) {
	n, r, p = e.ScryptN, e.ScryptR, e.ScryptP
	if n == 0 {
		n = scryptN
	}
	if r == 0 {
		r = scryptR
	}
	if p == 0 {
		p = scryptP
	}
	return n, r, p
}

// Vault is the mutable store persisted alongside the binary.
type Vault struct {
	Entries []Entry `json:"entries"`
}

// Find returns the entry with the given name, if any.
func (v *Vault) Find(name string) (*Entry, bool) {
	for i := range v.Entries {
		if v.Entries[i].Name == name {
			return &v.Entries[i], true
		}
	}
	return nil, false
}

// Upsert appends e, or replaces the existing entry with the same name.
func (v *Vault) Upsert(e Entry) {
	for i := range v.Entries {
		if v.Entries[i].Name == e.Name {
			v.Entries[i] = e
			return
		}
	}
	v.Entries = append(v.Entries, e)
}

// VerifySecret reports whether secret can decrypt the vault's first entry —
// i.e. whether it is this vault's shared secret. All entries in a vault are
// sealed under the same secret, so checking one is sufficient.
func (v *Vault) VerifySecret(env string, secret []byte) error {
	if len(v.Entries) == 0 {
		return errors.New("vault has no entries to verify against")
	}
	if _, err := OpenEntry(env, v.Entries[0], secret); err != nil {
		return errors.New("secret does not match this vault")
	}
	return nil
}

// Rotate re-encrypts every entry in v under newSecret, replacing oldSecret.
// It verifies oldSecret against the vault first, and fails without
// modifying v if it doesn't match. Rotation is all-or-nothing: entries are
// decrypted and re-sealed into a separate slice, and v.Entries is only
// reassigned once every entry has succeeded — so a vault is never left with
// some entries under the old secret and some under the new one. Because
// SealEntry always records the package's current scrypt cost parameters, an
// entry rotated with an older, lower-cost params also picks up today's cost
// as a side effect.
func (v *Vault) Rotate(env string, oldSecret, newSecret []byte) error {
	if err := v.VerifySecret(env, oldSecret); err != nil {
		return err
	}
	rotated := make([]Entry, len(v.Entries))
	for i, e := range v.Entries {
		plain, err := OpenEntry(env, e, oldSecret)
		if err != nil {
			return err
		}
		sealed, err := SealEntry(env, e.Name, newSecret, plain)
		Zero(plain)
		if err != nil {
			return err
		}
		sealed.OrigName = e.OrigName
		rotated[i] = sealed
	}
	v.Entries = rotated
	return nil
}

// SealEntry encrypts plain for the given vault+name with a fresh per-entry
// salt and nonce, binding the ciphertext to both names via AEAD additional
// data. The entry records the package's current scrypt cost parameters, so
// a later change to those defaults doesn't affect how this entry opens.
func SealEntry(env, name string, secret, plain []byte) (Entry, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return Entry{}, err
	}
	gcm, err := newGCM(secret, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return Entry{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Entry{}, err
	}
	ct := gcm.Seal(nil, nonce, plain, aad(env, name))
	return Entry{
		Name:       name,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ct,
		ScryptN:    scryptN,
		ScryptR:    scryptR,
		ScryptP:    scryptP,
	}, nil
}

// OpenEntry decrypts e, which must belong to vault env. It fails if secret
// is wrong or the ciphertext was tampered with. It derives the key using
// e's own recorded scrypt cost parameters (see Entry.scryptParams), not
// necessarily the package's current ones — so an entry sealed under an
// older cost still opens correctly after that cost is later raised.
func OpenEntry(env string, e Entry, secret []byte) ([]byte, error) {
	n, r, p := e.scryptParams()
	gcm, err := newGCM(secret, e.Salt, n, r, p)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, e.Nonce, e.Ciphertext, aad(env, e.Name))
	if err != nil {
		return nil, errors.New("incorrect secret or corrupted entry")
	}
	return plain, nil
}

func newGCM(secret, salt []byte, n, r, p int) (cipher.AEAD, error) {
	key, err := scrypt.Key(secret, salt, n, r, p, keyLen)
	if err != nil {
		return nil, err
	}
	defer Zero(key) // aes.NewCipher copies key into its own expanded schedule
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad returns the additional authenticated data binding an entry to its
// vault and name.
func aad(env, name string) []byte { return []byte(env + "\x00" + name) }

// Store locates vault sidecar files on disk.
type Store struct {
	// Dir is the directory containing vault.<name>.json files. Empty means
	// the current working directory.
	Dir string
}

// PathFor returns the sidecar file path for the named vault.
func (s Store) PathFor(name string) string {
	return filepath.Join(s.Dir, "vault."+name+".json")
}

// CheckPermissions reports whether the named vault's sidecar file has
// looser-than-expected permissions. See CheckFilePermissions.
func (s Store) CheckPermissions(name string) (string, error) {
	return CheckFilePermissions(s.PathFor(name))
}

// CheckFilePermissions stats path and returns a non-empty warning if its
// permission bits allow group or other access — Store.Save always writes
// 0600, so anything looser means something after the fact (a manual chmod,
// a careless cp, an umask, a sync to a shared filesystem) widened it.
//
// This is a Unix permissions concept: on Windows, os.FileMode doesn't
// reflect real ACLs (Go synthesizes it from the read-only attribute alone),
// so the check is a no-op there. It also does nothing if path doesn't
// exist — there's nothing to warn about yet.
func CheckFilePermissions(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("warning: %s is readable by group/other (mode %04o, expected 0600)", path, perm), nil
	}
	return "", nil
}

// Load reads the named vault, returning an empty Vault if it doesn't exist
// yet.
func (s Store) Load(name string) (*Vault, error) {
	data, err := os.ReadFile(s.PathFor(name))
	if errors.Is(err, os.ErrNotExist) {
		return &Vault{}, nil
	}
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Save persists v as the named vault, writing atomically-ish via a temp
// file + rename.
func (s Store) Save(name string, v *Vault) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := s.PathFor(name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Summary describes one vault discovered on disk.
type Summary struct {
	Name     string
	Path     string
	Entries  int
	Readable bool // false if the file could not be parsed as a vault
}

// List discovers every vault.<name>.json in the store's directory.
func (s Store) List() ([]Summary, error) {
	matches, err := filepath.Glob(filepath.Join(s.Dir, "vault.*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := make([]Summary, 0, len(matches))
	for _, path := range matches {
		base := filepath.Base(path)
		name := strings.TrimSuffix(strings.TrimPrefix(base, "vault."), ".json")
		sum := Summary{Name: name, Path: path}
		if data, err := os.ReadFile(path); err == nil {
			var v Vault
			if json.Unmarshal(data, &v) == nil {
				sum.Readable = true
				sum.Entries = len(v.Entries)
			}
		}
		out = append(out, sum)
	}
	return out, nil
}
