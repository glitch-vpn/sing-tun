//go:build windows

package winipcfg

import (
	"net/netip"
	"testing"
)

func TestARouteSetByACallerIsClearedWhateverItCovers(t *testing.T) {
	const ours, other = LUID(42), LUID(7)
	route := func(luid LUID, prefix string, protocol RouteProtocol) *MibIPforwardRow2 {
		row := &MibIPforwardRow2{InterfaceLUID: luid, Protocol: protocol}
		if err := row.DestinationPrefix.SetPrefix(netip.MustParsePrefix(prefix)); err != nil {
			t.Fatal(err)
		}
		return row
	}
	for _, c := range []struct {
		name string
		row  *MibIPforwardRow2
		want bool
	}{
		{"the last part of a split default route", route(ours, "224.0.0.0/3", RouteProtocolNetMgmt), true},
		{"a split default route's first part", route(ours, "0.0.0.0/1", RouteProtocolNetMgmt), true},
		{"Windows' multicast route", route(ours, "224.0.0.0/4", RouteProtocolLocal), false},
		{"Windows' broadcast route", route(ours, "255.255.255.255/32", RouteProtocolLocal), false},
		{"Windows' link-local route", route(ours, "fe80::/64", RouteProtocolLocal), false},
		{"another interface's route", route(other, "0.0.0.0/1", RouteProtocolNetMgmt), false},
	} {
		if got := c.row.setByCallerOn(ours); got != c.want {
			t.Errorf("%s: setByCallerOn = %v, want %v", c.name, got, c.want)
		}
	}
}
