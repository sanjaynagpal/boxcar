package vault

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	secret := []byte("correct-secret")
	e, err := SealEntry("dev", "note", secret, []byte("hello world"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	plain, err := OpenEntry("dev", e, secret)
	if err != nil {
		t.Fatalf("OpenEntry: %v", err)
	}
	if string(plain) != "hello world" {
		t.Fatalf("got %q, want %q", plain, "hello world")
	}
}

func TestOpenEntry_WrongSecret(t *testing.T) {
	e, err := SealEntry("dev", "note", []byte("correct-secret"), []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	if _, err := OpenEntry("dev", e, []byte("wrong-secret!")); err == nil {
		t.Fatal("OpenEntry succeeded with the wrong secret")
	}
}

func TestOpenEntry_AADBindsVaultName(t *testing.T) {
	secret := []byte("correct-secret")
	e, err := SealEntry("dev", "note", secret, []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	if _, err := OpenEntry("prod", e, secret); err == nil {
		t.Fatal("OpenEntry succeeded after moving the entry to a different vault")
	}
}

func TestOpenEntry_AADBindsEntryName(t *testing.T) {
	secret := []byte("correct-secret")
	e, err := SealEntry("dev", "note", secret, []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	e.Name = "renamed"
	if _, err := OpenEntry("dev", e, secret); err == nil {
		t.Fatal("OpenEntry succeeded after renaming the entry")
	}
}

func TestSealEntry_RecordsCurrentScryptParams(t *testing.T) {
	e, err := SealEntry("dev", "note", []byte("correct-secret"), []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	if e.ScryptN != scryptN || e.ScryptR != scryptR || e.ScryptP != scryptP {
		t.Fatalf("got scrypt params (%d,%d,%d), want (%d,%d,%d)",
			e.ScryptN, e.ScryptR, e.ScryptP, scryptN, scryptR, scryptP)
	}
}

// sealWithParams builds an Entry the way SealEntry does, but under caller-
// supplied scrypt cost parameters, so tests can simulate an entry sealed
// under a cost different from the package's current consts.
func sealWithParams(t *testing.T, env, name string, secret, plain []byte, n, r, p int) Entry {
	t.Helper()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read salt: %v", err)
	}
	gcm, err := newGCM(secret, salt, n, r, p)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plain, aad(env, name))
	return Entry{Name: name, Salt: salt, Nonce: nonce, Ciphertext: ct}
}

func TestOpenEntry_UsesEntrysOwnScryptParams(t *testing.T) {
	secret := []byte("correct-secret")
	// Deliberately different (lower) cost than the package's current
	// consts, simulating an entry sealed before those consts were raised.
	oldN, oldR, oldP := 1<<10, 4, 1
	e := sealWithParams(t, "dev", "note", secret, []byte("hello"), oldN, oldR, oldP)
	e.ScryptN, e.ScryptR, e.ScryptP = oldN, oldR, oldP

	plain, err := OpenEntry("dev", e, secret)
	if err != nil {
		t.Fatalf("OpenEntry with the entry's own (lower) scrypt params: %v", err)
	}
	if string(plain) != "hello" {
		t.Fatalf("got %q, want %q", plain, "hello")
	}
}

func TestOpenEntry_LegacyEntryWithoutScryptParams(t *testing.T) {
	// An entry sealed before ScryptN/R/P existed unmarshals with those
	// fields at their zero value. OpenEntry must fall back to the
	// package's current consts to open it — exactly what it was sealed
	// under here, since sealWithParams(..., scryptN, scryptR, scryptP)
	// matches what SealEntry itself would have used.
	secret := []byte("correct-secret")
	legacy := sealWithParams(t, "dev", "note", secret, []byte("hello"), scryptN, scryptR, scryptP)
	// legacy.ScryptN/R/P are left at zero, as if unmarshaled from JSON
	// that predates the field.

	plain, err := OpenEntry("dev", legacy, secret)
	if err != nil {
		t.Fatalf("OpenEntry (legacy entry, zero scrypt params): %v", err)
	}
	if string(plain) != "hello" {
		t.Fatalf("got %q, want %q", plain, "hello")
	}
}

func TestStore_Load_LegacyVaultJSONWithoutScryptParams(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("correct-secret")

	e, err := SealEntry("dev", "note", secret, []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}

	// Write it out as "legacy" JSON: the exact shape a vault.<name>.json
	// would have had before scryptN/scryptR/scryptP existed as fields.
	legacyJSON := fmt.Sprintf(`{"entries":[{"name":%q,"salt":%q,"nonce":%q,"ciphertext":%q}]}`,
		e.Name,
		base64.StdEncoding.EncodeToString(e.Salt),
		base64.StdEncoding.EncodeToString(e.Nonce),
		base64.StdEncoding.EncodeToString(e.Ciphertext))
	path := filepath.Join(dir, "vault.dev.json")
	if err := os.WriteFile(path, []byte(legacyJSON), 0o600); err != nil {
		t.Fatalf("write legacy vault JSON: %v", err)
	}

	v, err := (Store{Dir: dir}).Load("dev")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := v.Find("note")
	if !ok {
		t.Fatal("entry not found after loading legacy vault JSON")
	}
	if got.ScryptN != 0 || got.ScryptR != 0 || got.ScryptP != 0 {
		t.Fatalf("got scrypt params (%d,%d,%d), want (0,0,0) for a legacy entry",
			got.ScryptN, got.ScryptR, got.ScryptP)
	}

	plain, err := OpenEntry("dev", *got, secret)
	if err != nil {
		t.Fatalf("OpenEntry (entry loaded from legacy JSON): %v", err)
	}
	if string(plain) != "hello" {
		t.Fatalf("got %q, want %q", plain, "hello")
	}
}

func TestVault_UpsertReplacesByName(t *testing.T) {
	var v Vault
	v.Upsert(Entry{Name: "a", Ciphertext: []byte("1")})
	v.Upsert(Entry{Name: "b", Ciphertext: []byte("2")})
	v.Upsert(Entry{Name: "a", Ciphertext: []byte("3")})

	if len(v.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(v.Entries))
	}
	e, ok := v.Find("a")
	if !ok {
		t.Fatal("entry \"a\" not found")
	}
	if string(e.Ciphertext) != "3" {
		t.Fatalf("entry \"a\" not replaced, got ciphertext %q", e.Ciphertext)
	}
}

func TestVault_VerifySecret(t *testing.T) {
	secret := []byte("correct-secret")
	var v Vault
	e, err := SealEntry("dev", "note", secret, []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	v.Upsert(e)

	if err := v.VerifySecret("dev", secret); err != nil {
		t.Fatalf("VerifySecret with correct secret: %v", err)
	}
	if err := v.VerifySecret("dev", []byte("wrong-secret!")); err == nil {
		t.Fatal("VerifySecret succeeded with the wrong secret")
	}

	var empty Vault
	if err := empty.VerifySecret("dev", secret); err == nil {
		t.Fatal("VerifySecret succeeded against an empty vault")
	}
}

func TestVault_Rotate_RoundTrip(t *testing.T) {
	var v Vault
	oldSecret := []byte("correct-secret")
	newSecret := []byte("brand-new-secret")

	for _, name := range []string{"a", "b"} {
		e, err := SealEntry("dev", name, oldSecret, []byte("content-"+name))
		if err != nil {
			t.Fatalf("SealEntry(%q): %v", name, err)
		}
		v.Upsert(e)
	}

	if err := v.Rotate("dev", oldSecret, newSecret); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if err := v.VerifySecret("dev", oldSecret); err == nil {
		t.Fatal("VerifySecret succeeded with the pre-rotation secret")
	}
	if err := v.VerifySecret("dev", newSecret); err != nil {
		t.Fatalf("VerifySecret with the new secret: %v", err)
	}

	for _, name := range []string{"a", "b"} {
		e, ok := v.Find(name)
		if !ok {
			t.Fatalf("entry %q missing after rotate", name)
		}
		plain, err := OpenEntry("dev", *e, newSecret)
		if err != nil {
			t.Fatalf("OpenEntry(%q) with the new secret: %v", name, err)
		}
		if string(plain) != "content-"+name {
			t.Fatalf("entry %q content = %q, want %q", name, plain, "content-"+name)
		}
	}
}

func TestVault_Rotate_PreservesOrigName(t *testing.T) {
	var v Vault
	oldSecret := []byte("correct-secret")
	newSecret := []byte("brand-new-secret")

	e, err := SealEntry("dev", "db", oldSecret, []byte("content"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	e.OrigName = "db-password.txt"
	v.Upsert(e)

	if err := v.Rotate("dev", oldSecret, newSecret); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	got, ok := v.Find("db")
	if !ok {
		t.Fatal("entry missing after rotate")
	}
	if got.OrigName != "db-password.txt" {
		t.Fatalf("OrigName after rotate = %q, want %q", got.OrigName, "db-password.txt")
	}
}

func TestVault_Rotate_WrongOldSecretLeavesVaultUnmodified(t *testing.T) {
	var v Vault
	e, err := SealEntry("dev", "a", []byte("correct-secret"), []byte("content"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	v.Upsert(e)
	before := append([]byte(nil), v.Entries[0].Ciphertext...)

	if err := v.Rotate("dev", []byte("wrong-secret!"), []byte("brand-new-secret")); err == nil {
		t.Fatal("Rotate succeeded with the wrong old secret")
	}

	if len(v.Entries) != 1 || string(v.Entries[0].Ciphertext) != string(before) {
		t.Fatal("vault was modified despite Rotate failing")
	}
}

func TestVault_Rotate_EmptyVault(t *testing.T) {
	var v Vault
	if err := v.Rotate("dev", []byte("correct-secret"), []byte("brand-new-secret")); err == nil {
		t.Fatal("Rotate succeeded on an empty vault")
	}
}

func TestIsValidName(t *testing.T) {
	valid := []string{"dev", "prod", "team-a", "ci_1", "a"}
	for _, n := range valid {
		if !IsValidName(n) {
			t.Errorf("IsValidName(%q) = false, want true", n)
		}
	}
	invalid := []string{"", "has space", "../etc", "a/b", strings.Repeat("a", 65)}
	for _, n := range invalid {
		if IsValidName(n) {
			t.Errorf("IsValidName(%q) = true, want false", n)
		}
	}
}

func TestStore_LoadSaveRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}

	// Loading a vault that doesn't exist yet returns an empty vault, not an error.
	v, err := s.Load("dev")
	if err != nil {
		t.Fatalf("Load (missing): %v", err)
	}
	if len(v.Entries) != 0 {
		t.Fatalf("got %d entries, want 0", len(v.Entries))
	}

	e, err := SealEntry("dev", "note", []byte("correct-secret"), []byte("hello"))
	if err != nil {
		t.Fatalf("SealEntry: %v", err)
	}
	v.Upsert(e)
	if err := s.Save("dev", v); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Load("dev")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Name != "note" {
		t.Fatalf("got %+v, want one entry named \"note\"", got.Entries)
	}

	wantPath := filepath.Join(s.Dir, "vault.dev.json")
	if s.PathFor("dev") != wantPath {
		t.Fatalf("PathFor = %q, want %q", s.PathFor("dev"), wantPath)
	}
}

func TestStore_List(t *testing.T) {
	s := Store{Dir: t.TempDir()}

	if err := s.Save("dev", &Vault{}); err != nil {
		t.Fatalf("Save dev: %v", err)
	}
	e, _ := SealEntry("prod", "note", []byte("correct-secret"), []byte("hello"))
	if err := s.Save("prod", &Vault{Entries: []Entry{e}}); err != nil {
		t.Fatalf("Save prod: %v", err)
	}

	summaries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("got %d summaries, want 2", len(summaries))
	}
	byName := map[string]Summary{}
	for _, sum := range summaries {
		byName[sum.Name] = sum
	}
	if sum := byName["dev"]; !sum.Readable || sum.Entries != 0 {
		t.Errorf("dev summary = %+v, want readable with 0 entries", sum)
	}
	if sum := byName["prod"]; !sum.Readable || sum.Entries != 1 {
		t.Errorf("prod summary = %+v, want readable with 1 entry", sum)
	}
}

func TestIsWeakSecret(t *testing.T) {
	weak := []string{
		"short",          // under RecommendedSecretLen
		"password",       // common, and also short
		"correct-secret", // 14 chars: passes MinSecretLen but under RecommendedSecretLen (16)
		"PaSsWoRd1",      // common, case-insensitive match
		"Admin",          // common, case-insensitive match
	}
	for _, s := range weak {
		if !IsWeakSecret([]byte(s)) {
			t.Errorf("IsWeakSecret(%q) = false, want true", s)
		}
	}

	strong := []string{
		"correct-horse-battery-staple", // long, not in the common list
		strings.Repeat("x", RecommendedSecretLen),
	}
	for _, s := range strong {
		if IsWeakSecret([]byte(s)) {
			t.Errorf("IsWeakSecret(%q) = true, want false", s)
		}
	}
}

func TestZero(t *testing.T) {
	b := []byte("correct-secret")
	Zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d = %q, want 0", i, c)
		}
	}

	// Must not panic on an empty or nil slice.
	Zero(nil)
	Zero([]byte{})
}

func TestCheckSecretLength(t *testing.T) {
	if err := CheckSecretLength([]byte("short")); err == nil {
		t.Error("CheckSecretLength(\"short\") = nil, want error")
	}
	if err := CheckSecretLength([]byte("longenough")); err != nil {
		t.Errorf("CheckSecretLength(\"longenough\") = %v, want nil", err)
	}
}

func TestCheckFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.dev.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	msg, err := CheckFilePermissions(path)
	if err != nil {
		t.Fatalf("CheckFilePermissions: %v", err)
	}
	if runtime.GOOS == "windows" {
		// os.FileMode bits aren't real ACLs on Windows; the check is a no-op there.
		if msg != "" {
			t.Errorf("got warning %q on windows, want none", msg)
		}
	} else if msg == "" {
		t.Error("got no warning for a 0644 file, want one")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		msg, err := CheckFilePermissions(path)
		if err != nil {
			t.Fatalf("CheckFilePermissions: %v", err)
		}
		if msg != "" {
			t.Errorf("got warning %q for a 0600 file, want none", msg)
		}
	}

	msg, err = CheckFilePermissions(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatalf("CheckFilePermissions (missing file): %v", err)
	}
	if msg != "" {
		t.Errorf("got warning %q for a missing file, want none", msg)
	}
}

func TestStore_CheckPermissions(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.Save("dev", &Vault{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Store.Save always writes 0600, so a freshly saved vault should never warn.
	msg, err := s.CheckPermissions("dev")
	if err != nil {
		t.Fatalf("CheckPermissions: %v", err)
	}
	if msg != "" {
		t.Errorf("got warning %q for a freshly saved vault, want none", msg)
	}
}
