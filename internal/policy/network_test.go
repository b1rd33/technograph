package policy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestIsPublic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true}, {"2606:4700:4700::1111", true},
		{"127.0.0.1", false}, {"10.1.2.3", false}, {"169.254.169.254", false},
		{"100.64.0.1", false}, {"192.0.2.1", false}, {"::1", false},
		{"fc00::1", false}, {"fe80::1", false}, {"2001:db8::1", false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := IsPublic(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("IsPublic(%s) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}

type staticResolver []net.IPAddr

func (resolver staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return resolver, nil
}

func TestSafeDialerRejectsMixedPublicAndPrivateResolution(t *testing.T) {
	dialer := SafeDialer{Resolver: staticResolver{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}}
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("error = %v, want ErrUnsafeAddress", err)
	}
}

func TestSafeDialerRejectsNonWebPorts(t *testing.T) {
	dialer := SafeDialer{}
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:22")
	if !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("error = %v, want ErrUnsafeAddress", err)
	}
}
