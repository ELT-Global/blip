// Package totp implements RFC 6238 time-based one-time passwords
// (HMAC-SHA1, 6 digits, 30 second steps) as used by authenticator apps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const period = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit key.
func NewSecret() []byte {
	k := make([]byte, 20)
	rand.Read(k)
	return k
}

// Encode returns the base32 form authenticator apps accept for manual entry.
func Encode(secret []byte) string { return b32.EncodeToString(secret) }

// URI returns the otpauth:// URI that enrollment QR codes carry.
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?secret=" + Encode(secret) + "&issuer=" + url.QueryEscape(issuer)
}

// Step returns the time step containing t.
func Step(t time.Time) int64 { return t.Unix() / period }

// Code returns the 6-digit code for a time step.
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// Verify checks code against the steps around now, tolerating one step of
// clock drift either way, and returns the matching step.
func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	s := Step(now)
	for _, st := range [...]int64{s, s - 1, s + 1} {
		if hmac.Equal([]byte(Code(secret, st)), []byte(code)) {
			return st, true
		}
	}
	return 0, false
}
