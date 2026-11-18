//go:build windows

package winipcfg

import "net/netip"

// FlushManagedRoutes deletes the routes on the interface that were set on it
// by a caller, and keeps the ones Windows gives every interface (the
// multicast, broadcast and link-local routes, and the prefix route of an
// address): those carry the local protocol, and as a second guard their
// destinations are never deleted. It continues on failures and returns the
// last error.
func (luid LUID) FlushManagedRoutes(family AddressFamily) error {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return err
	}
	defer tab.free()
	rows := tab.get()
	err = nil
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID != luid || row.Protocol != RouteProtocolNetMgmt || isSystemRouteDestination(row.DestinationPrefix.Prefix()) {
			continue
		}
		if err2 := row.Delete(); err2 != nil {
			err = err2
		}
	}
	return err
}

func isSystemRouteDestination(prefix netip.Prefix) bool {
	addr := prefix.Addr()
	return addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// FlushManualIPAddresses deletes the unicast addresses on the interface that a
// caller set by hand, and keeps the ones Windows gives it (an IPv6 link-local
// address is well-known, not manual). It continues on failures and returns the
// last error.
func (luid LUID) FlushManualIPAddresses(family AddressFamily) error {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return err
	}
	defer tab.free()
	rows := tab.get()
	err = nil
	for i := range rows {
		if rows[i].InterfaceLUID != luid || rows[i].PrefixOrigin != PrefixOriginManual {
			continue
		}
		if err2 := rows[i].Delete(); err2 != nil {
			err = err2
		}
	}
	return err
}
