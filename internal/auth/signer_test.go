package auth

import (
	"strings"
	"testing"
	"time"
)

type payload struct {
	A string `json:"a"`
}

func TestSignVerify(t *testing.T) {
	s := NewSigner([]byte(strings.Repeat("k", 32)))
	tok, err := s.Sign("state", payload{"x"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := s.Verify("state", tok, &got); err != nil || got.A != "x" {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	if err := s.Verify("session", tok, &got); err == nil {
		t.Error("token accepted for another purpose")
	}
	if err := NewSigner([]byte(strings.Repeat("o", 32))).Verify("state", tok, &got); err == nil {
		t.Error("token accepted under another key")
	}
	if err := s.Verify("state", tok[:len(tok)-2]+"AA", &got); err == nil {
		t.Error("tampered signature accepted")
	}
	if err := s.Verify("state", "garbage", &got); err == nil {
		t.Error("garbage accepted")
	}
	old, _ := s.Sign("state", payload{"x"}, -time.Second)
	if err := s.Verify("state", old, &got); err == nil {
		t.Error("expired token accepted")
	}
}
