//go:build windows

package winipcfg

// FlushManagedRoutes deletes the routes on the interface that were set on it
// by a caller, and keeps the ones Windows gives every interface (the
// multicast, broadcast and link-local routes, and the prefix route of an
// address), which carry the local protocol. A caller's route may cover those
// ranges: a default route split in parts ends in 224.0.0.0/3. It continues on
// failures and returns the last error.
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
		if !row.setByCallerOn(luid) {
			continue
		}
		if err2 := row.Delete(); err2 != nil {
			err = err2
		}
	}
	return err
}

// setByCallerOn reports whether a caller set the route on the interface.
func (row *MibIPforwardRow2) setByCallerOn(luid LUID) bool {
	return row.InterfaceLUID == luid && row.Protocol == RouteProtocolNetMgmt
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
