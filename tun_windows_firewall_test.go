//go:build windows

package tun

import (
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/metacubex/sing-tun/internal/winsys"

	"github.com/stretchr/testify/require"
)

// addedFilter keeps the conditions the filter pointed at when it was added,
// since the caller may reuse the condition slice for the next filter.
type addedFilter struct {
	winsys.FWPM_FILTER0
	conditions []winsys.FWPM_FILTER_CONDITION0
}

type fakeFirewallEngine struct {
	filters   []addedFilter
	failAfter int // filters accepted before addFilter fails; -1 never fails
	closed    int
}

func (e *fakeFirewallEngine) addSubLayer(*winsys.FWPM_SUBLAYER0) error { return nil }

func (e *fakeFirewallEngine) addFilter(filter *winsys.FWPM_FILTER0) error {
	if e.failAfter >= 0 && len(e.filters) >= e.failAfter {
		return errors.New("injected filter failure")
	}
	added := addedFilter{FWPM_FILTER0: *filter}
	if filter.NumFilterConditions > 0 {
		added.conditions = append(added.conditions, unsafe.Slice(filter.FilterCondition, filter.NumFilterConditions)...)
	}
	e.filters = append(e.filters, added)
	return nil
}

func (e *fakeFirewallEngine) close() error {
	e.closed++
	return nil
}

// matches reports whether a connection to the remote address and port meets
// every condition; a condition on anything else (application, ICMP) does not.
func (f addedFilter) matches(remote netip.Addr, port uint16) bool {
	for _, condition := range f.conditions {
		value := condition.ConditionValue
		switch {
		case condition.FieldKey == winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS && value.Type == winsys.FWP_V6_ADDR_MASK && condition.MatchType == winsys.FWP_MATCH_EQUAL:
			mask := *(**winsys.FWP_V6_ADDR_AND_MASK)(unsafe.Pointer(&value.Value))
			if !netip.PrefixFrom(netip.AddrFrom16(mask.Addr), int(mask.PrefixLength)).Contains(remote) {
				return false
			}
		case condition.FieldKey == winsys.FWPM_CONDITION_IP_REMOTE_PORT && value.Type == winsys.FWP_UINT16:
			equal := uint16(value.Value) == port
			if equal != (condition.MatchType == winsys.FWP_MATCH_EQUAL) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ipv6Verdict is the action of the highest weight IPv6 filter that matches,
// or FWP_ACTION_PERMIT when none does.
func (e *fakeFirewallEngine) ipv6Verdict(remote string, port uint16) uint32 {
	address := netip.MustParseAddr(remote)
	verdict := winsys.FWP_ACTION_PERMIT
	var topWeight uintptr
	matched := false
	for _, filter := range e.filters {
		if filter.LayerKey != winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6 || !filter.matches(address, port) {
			continue
		}
		if !matched || filter.Weight.Value > topWeight {
			matched, topWeight, verdict = true, filter.Weight.Value, filter.Action.Type
		}
	}
	return verdict
}

func useFakeFirewall(t *testing.T, failAfter int) *fakeFirewallEngine {
	engine := &fakeFirewallEngine{failAfter: failAfter}
	openFirewallEngine = func() (firewallEngine, error) { return engine, nil }
	lookupInterfaceIndex = func(uint64) (uint32, error) { return 7, nil }
	t.Cleanup(func() {
		openFirewallEngine = openWindowsFirewallEngine
	})
	return engine
}

func strictRouteTun(options Options) *NativeTun {
	options.AutoRoute = true
	options.StrictRoute = true
	return &NativeTun{options: options, adapter: &fakeAdapter{luid: 42}, luid: 42}
}

var localIPv6Remotes = []string{"fe80::1", "fc00::1", "fd12:3456::1", "ff02::fb"}

func requireIPv6Verdict(t *testing.T, engine *fakeFirewallEngine, remote string, port uint16, verdict uint32) {
	t.Helper()
	require.Equal(t, verdict, engine.ipv6Verdict(remote, port), "%s port %d", remote, port)
}

func ipv4Only(options Options) Options {
	options.Name = "test"
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}
	return options
}

// Without an IPv6 address on the TUN, a strict route blocks global IPv6 for
// every process but the core and lets loopback through.
func TestStrictRouteWithoutTunIPv6KeepsLoopback(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	require.NoError(t, strictRouteTun(ipv4Only(Options{})).configureFirewall())
	requireIPv6Verdict(t, engine, "::1", 443, winsys.FWP_ACTION_PERMIT)
	requireIPv6Verdict(t, engine, "2001:db8::1", 443, winsys.FWP_ACTION_BLOCK)
	for _, remote := range localIPv6Remotes {
		requireIPv6Verdict(t, engine, remote, 443, winsys.FWP_ACTION_BLOCK)
	}
}

// With local networks direct, link-local, unique local and multicast IPv6 pass
// as well, and global IPv6 stays blocked.
func TestStrictRouteWithoutTunIPv6PermitsLocalNetworksWhenDirect(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	require.NoError(t, strictRouteTun(ipv4Only(Options{StrictRouteLocalNetworksDirect: true})).configureFirewall())
	requireIPv6Verdict(t, engine, "::1", 443, winsys.FWP_ACTION_PERMIT)
	requireIPv6Verdict(t, engine, "2001:db8::1", 443, winsys.FWP_ACTION_BLOCK)
	for _, remote := range localIPv6Remotes {
		requireIPv6Verdict(t, engine, remote, 443, winsys.FWP_ACTION_PERMIT)
	}
}

// DNS hijack keeps a query to a local resolver from passing the permits for
// local networks, whatever the prefix.
func TestStrictRouteLocalNetworksDirectBlocksDNSUnderHijack(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	options := ipv4Only(Options{StrictRouteLocalNetworksDirect: true, DNSMode: DNSModeHijack})
	require.NoError(t, strictRouteTun(options).configureFirewall())
	for _, remote := range append([]string{"::1"}, localIPv6Remotes...) {
		requireIPv6Verdict(t, engine, remote, 53, winsys.FWP_ACTION_BLOCK)
		requireIPv6Verdict(t, engine, remote, 443, winsys.FWP_ACTION_PERMIT)
	}
	requireIPv6Verdict(t, engine, "2001:db8::1", 443, winsys.FWP_ACTION_BLOCK)
	for _, filter := range engine.filters {
		for _, condition := range filter.conditions {
			require.NotEqual(t, uint32(winsys.FWP_MATCH_NOT_EQUAL), uint32(condition.MatchType))
		}
	}
}

// The core's own IPv6 connections must outweigh every block, the local
// resolvers' port 53 blocks included.
func TestStrictRouteCoreIPv6PermitOutweighsBlocks(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	options := ipv4Only(Options{StrictRouteLocalNetworksDirect: true, DNSMode: DNSModeHijack})
	require.NoError(t, strictRouteTun(options).configureFirewall())
	var coreWeight, topBlockWeight uintptr
	for _, filter := range engine.filters {
		if filter.LayerKey != winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
			continue
		}
		if len(filter.conditions) == 1 && filter.conditions[0].FieldKey == winsys.FWPM_CONDITION_ALE_APP_ID {
			coreWeight = filter.Weight.Value
		}
		if filter.Action.Type == winsys.FWP_ACTION_BLOCK && filter.Weight.Value > topBlockWeight {
			topBlockWeight = filter.Weight.Value
		}
	}
	require.Greater(t, coreWeight, topBlockWeight)
}

// Neighbor discovery filters each keep their own ICMP type.
func TestStrictRouteWithoutTunIPv6PermitsNeighborDiscovery(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	require.NoError(t, strictRouteTun(ipv4Only(Options{})).configureFirewall())
	var icmpTypes []uintptr
	for _, filter := range engine.filters {
		for _, condition := range filter.conditions {
			if condition.FieldKey == winsys.FWPM_CONDITION_ICMP_TYPE {
				icmpTypes = append(icmpTypes, condition.ConditionValue.Value)
			}
		}
	}
	require.Equal(t, []uintptr{133, 135, 136}, icmpTypes)
}

// With an IPv6 address on the TUN there is no IPv6 block, so the permits for
// local prefixes are not added either.
func TestStrictRouteWithTunIPv6HasNoIPv6Block(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	options := Options{Name: "test", Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}}
	require.NoError(t, strictRouteTun(options).configureFirewall())
	requireIPv6Verdict(t, engine, "2001:db8::1", 443, winsys.FWP_ACTION_PERMIT)
	requireIPv6Verdict(t, engine, "fe80::1", 443, winsys.FWP_ACTION_PERMIT)
}

// A filter that fails to install must not leave the session open, since the
// port 53 and IPv6 blocks stay machine-wide while it is.
func TestFailedStrictRouteClosesFirewallSession(t *testing.T) {
	options := Options{Name: "test", DNSMode: DNSModeHijack, Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}}
	complete := useFakeFirewall(t, -1)
	require.NoError(t, strictRouteTun(options).configureFirewall())
	require.NotEmpty(t, complete.filters)
	for failAfter := 0; failAfter < len(complete.filters); failAfter++ {
		engine := useFakeFirewall(t, failAfter)
		tun := strictRouteTun(options)
		err := tun.configureFirewall()
		require.Error(t, err, "failAfter=%d", failAfter)
		require.Equal(t, 1, engine.closed, "failAfter=%d", failAfter)
		require.Nil(t, tun.firewall)
	}
}

// A strict route that installed is released when the tunnel closes.
func TestClosedStrictRouteClosesFirewallSession(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	tun := strictRouteTun(Options{Name: "test", Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}})
	require.NoError(t, tun.configureFirewall())
	require.Zero(t, engine.closed)
	tun.closeFirewall()
	tun.closeFirewall()
	require.Equal(t, 1, engine.closed)
}
