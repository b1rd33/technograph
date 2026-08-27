package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrUnsafeAddress marks a target rejected by the autonomous network policy.
var ErrUnsafeAddress = errors.New("unsafe network target")

type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// SafeDialer resolves once, rejects any special-use result, and dials the
// validated IP directly. This prevents redirects and DNS rebinding from
// turning an agent-requested public scan into access to a private service.
type SafeDialer struct {
	Resolver IPResolver
	Dialer   *net.Dialer
}

// DialContext implements net.Dialer's shape for http.Transport.
func (safe SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid address: %v", ErrUnsafeAddress, err)
	}
	if port != "80" && port != "443" {
		return nil, fmt.Errorf("%w: port %s is not allowed", ErrUnsafeAddress, port)
	}
	resolver := safe.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := safe.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	addresses := []net.IPAddr{}
	if literal := net.ParseIP(host); literal != nil {
		addresses = append(addresses, net.IPAddr{IP: literal})
	} else {
		addresses, err = resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}

	for _, candidate := range addresses {
		address, ok := netip.AddrFromSlice(candidate.IP)
		if !ok || !IsPublic(address.Unmap()) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrUnsafeAddress, host, candidate.IP)
		}
	}

	var lastErr error
	for _, candidate := range addresses {
		target := net.JoinHostPort(candidate.IP.String(), port)
		connection, dialErr := dialer.DialContext(ctx, network, target)
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("dial validated target %s: %w", host, lastErr)
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// IsPublic reports whether an IP can be contacted by autonomous scan modes.
func IsPublic(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
