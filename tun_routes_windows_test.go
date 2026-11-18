//go:build windows

package tun

import (
	"errors"
	"net/netip"
	"testing"
)

func TestARouteThatFailsStopsTheRestEvenWhenLaterOnesWouldSucceed(t *testing.T) {
	refused := errors.New("the object already exists")
	ranges := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/2"),
		netip.MustParsePrefix("224.0.0.0/3"),
	}
	var added []netip.Prefix
	err := addRoutes(ranges, func(prefix netip.Prefix) error {
		if prefix == ranges[0] {
			return refused
		}
		added = append(added, prefix)
		return nil
	})
	if !errors.Is(err, refused) {
		t.Errorf("err = %v, want the first route's refusal", err)
	}
	if len(added) != 0 {
		t.Errorf("added %v after the first route failed", added)
	}
}
