//go:build windows

package tun

import "net/netip"

// addRoutes adds each route and stops at the first that fails: a session that
// started without one of its routes would send that range outside the tunnel.
func addRoutes(routeRanges []netip.Prefix, add func(netip.Prefix) error) error {
	for _, routeRange := range routeRanges {
		if err := add(routeRange); err != nil {
			return err
		}
	}
	return nil
}
