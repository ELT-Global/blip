package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA1), truncated to 6 digits.
func TestCodeRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := Code(secret, tc.unix/30); got != tc.want {
			t.Errorf("Code(t=%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyDriftWindow(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_700_000_000, 0)
	s := Step(now)
	for d, ok := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		st, got := Verify(secret, Code(secret, s+d), now)
		if got != ok || (ok && st != s+d) {
			t.Errorf("drift %d: Verify = (%d, %v), want ok=%v step=%d", d, st, got, ok, s+d)
		}
	}
	if _, ok := Verify(secret, "12345", now); ok {
		t.Error("accepted a 5-digit code")
	}
}

func TestURI(t *testing.T) {
	got := URI("blip", "a+b@x.io", []byte("12345678901234567890"))
	want := "otpauth://totp/blip:a+b@x.io?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=blip"
	if got != want {
		t.Errorf("URI = %s\nwant  %s", got, want)
	}
}
