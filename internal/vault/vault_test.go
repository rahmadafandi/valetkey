package vault

import (
	"bytes"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRoundTrip(t *testing.T) {
	v, err := New(key(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed := v.Seal([]byte(`{"token":"abc"}`), []byte("u1/jenkins"))
	got, err := v.Open(sealed, []byte("u1/jenkins"))
	if err != nil || string(got) != `{"token":"abc"}` {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if bytes.Equal(sealed, v.Seal([]byte(`{"token":"abc"}`), []byte("u1/jenkins"))) {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestTamperFails(t *testing.T) {
	v, _ := New(key(1))
	sealed := v.Seal([]byte("secret"), []byte("a"))
	sealed[len(sealed)-1] ^= 0xff
	if _, err := v.Open(sealed, []byte("a")); err == nil {
		t.Error("tampered ciphertext opened")
	}
}

func TestWrongAADFails(t *testing.T) {
	v, _ := New(key(1))
	sealed := v.Seal([]byte("secret"), []byte("u1/jenkins"))
	if _, err := v.Open(sealed, []byte("u2/jenkins")); err == nil {
		t.Error("row moved to another user opened")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := New(key(1))
	b, _ := New(key(2))
	if _, err := b.Open(a.Seal([]byte("secret"), nil), nil); err == nil {
		t.Error("opened with the wrong key")
	}
}

func TestShortInput(t *testing.T) {
	v, _ := New(key(1))
	if _, err := v.Open([]byte{1, 2}, nil); err == nil {
		t.Error("short input opened")
	}
	if _, err := New(make([]byte, 16)); err == nil {
		t.Error("16-byte key accepted")
	}
}
