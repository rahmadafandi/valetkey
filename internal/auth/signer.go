// Package auth is valetkey's OAuth 2.1 authorization server, with Google as
// the identity source.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Signer makes tamper-proof, expiring tokens for state that round-trips
// through the browser (Google state, web session cookie), so it needs no table.
type Signer struct{ key []byte }

func NewSigner(key []byte) *Signer { return &Signer{key: key} }

type envelope struct {
	P   string          `json:"p"` // purpose: a session token is not a valid state token
	V   json.RawMessage `json:"v"`
	Exp int64           `json:"exp"`
}

var errBadToken = errors.New("invalid signed token")

func (s *Signer) Sign(purpose string, v any, ttl time.Duration) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(envelope{P: purpose, V: raw, Exp: time.Now().Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(s.mac(p)), nil
}

func (s *Signer) Verify(purpose, token string, v any) error {
	p, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(p)) {
		return errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return errBadToken
	}
	var e envelope
	if json.Unmarshal(payload, &e) != nil || e.P != purpose {
		return errBadToken
	}
	if time.Now().Unix() > e.Exp {
		return errors.New("signed token expired")
	}
	return json.Unmarshal(e.V, v)
}

func (s *Signer) mac(p string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(p))
	return m.Sum(nil)
}
