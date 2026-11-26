package monitor

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/ELT-Global/blip/internal/store"
)

func TestClassify(t *testing.T) {
	wrap := func(err error) error { return &url.Error{Op: "Get", URL: "http://secret.internal/x", Err: err} }
	for _, tc := range []struct {
		err  error
		code int
	}{
		{wrap(context.DeadlineExceeded), store.CodeTimeout},
		{wrap(&net.DNSError{Err: "no such host", Name: "secret.internal", IsNotFound: true}), store.CodeDNS},
		{wrap(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}), store.CodeRefused},
		{wrap(x509.UnknownAuthorityError{}), store.CodeTLS},
		{wrap(x509.HostnameError{Certificate: &x509.Certificate{}, Host: "secret.internal"}), store.CodeTLS},
		{wrap(errors.New("EOF")), store.CodeError},
	} {
		code := classify(tc.err)
		if code != tc.code {
			t.Errorf("classify(%v) = %d, want %d", tc.err, code, tc.code)
		}
		if c := cause(code, tc.err); c == "" || strings.Contains(c, "secret.internal") || strings.Contains(c, "http://") {
			t.Errorf("cause(%v) = %q, want a non-empty message without the target", tc.err, c)
		}
	}
}
