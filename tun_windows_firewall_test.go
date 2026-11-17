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

type fakeFirewallEngine struct {
	filters   []winsys.FWPM_FILTER0
	failAfter int // filters accepted before addFilter fails; -1 never fails
	closed    int
}

func (e *fakeFirewallEngine) addSubLayer(*winsys.FWPM_SUBLAYER0) error { return nil }

func (e *fakeFirewallEngine) addFilter(filter *winsys.FWPM_FILTER0) error {
	if e.failAfter >= 0 && len(e.filters) >= e.failAfter {
		return errors.New("injected filter failure")
	}
	e.filters = append(e.filters, *filter)
	return nil
}

func (e *fakeFirewallEngine) close() error {
	e.closed++
	return nil
}

func useFakeFirewall(t *testing.T, failAfter int) *fakeFirewallEngine {
	engine := &fakeFirewallEngine{failAfter: failAfter}
	openFirewallEngine = func() (firewallEngine, error) { return engine, nil }
	lookupInterfaceIndex = func(string) (uint32, error) { return 7, nil }
	t.Cleanup(func() {
		openFirewallEngine = openWindowsFirewallEngine
	})
	return engine
}

func strictRouteTun(options Options) *NativeTun {
	options.AutoRoute = true
	options.StrictRoute = true
	return &NativeTun{options: options}
}

// remotePrefixPermits lists the remote prefixes a permit filter of the IPv6
// connect layer matches on their own.
func remotePrefixPermits(engine *fakeFirewallEngine) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, filter := range engine.filters {
		if filter.LayerKey != winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6 || filter.Action.Type != winsys.FWP_ACTION_PERMIT || filter.NumFilterConditions != 1 {
			continue
		}
		condition := *filter.FilterCondition
		if condition.FieldKey != winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS || condition.ConditionValue.Type != winsys.FWP_V6_ADDR_MASK {
			continue
		}
		mask := *(**winsys.FWP_V6_ADDR_AND_MASK)(unsafe.Pointer(&condition.ConditionValue.Value))
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(mask.Addr), int(mask.PrefixLength)))
	}
	return prefixes
}

func hasIPv6Block(engine *fakeFirewallEngine) bool {
	for _, filter := range engine.filters {
		if filter.LayerKey == winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6 && filter.Action.Type == winsys.FWP_ACTION_BLOCK && filter.NumFilterConditions == 0 {
			return true
		}
	}
	return false
}

// Without an IPv6 address on the TUN, a strict route blocks global IPv6 for
// every process but the core and lets loopback through.
func TestStrictRouteWithoutTunIPv6KeepsLoopback(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	tun := strictRouteTun(Options{Name: "test", Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}})
	require.NoError(t, tun.configureFirewall())
	require.True(t, hasIPv6Block(engine))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("::1/128")}, remotePrefixPermits(engine))
}

// With local networks direct, link-local, unique local and multicast IPv6 pass
// as well.
func TestStrictRouteWithoutTunIPv6PermitsLocalNetworksWhenDirect(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	tun := strictRouteTun(Options{
		Name:                           "test",
		Inet4Address:                   []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		StrictRouteLocalNetworksDirect: true,
	})
	require.NoError(t, tun.configureFirewall())
	require.True(t, hasIPv6Block(engine))
	require.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}, remotePrefixPermits(engine))
}

// With an IPv6 address on the TUN there is no IPv6 block, so the permits for
// local prefixes are not added either.
func TestStrictRouteWithTunIPv6HasNoIPv6Block(t *testing.T) {
	engine := useFakeFirewall(t, -1)
	tun := strictRouteTun(Options{
		Name:         "test",
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
	})
	require.NoError(t, tun.configureFirewall())
	require.False(t, hasIPv6Block(engine))
	require.Empty(t, remotePrefixPermits(engine))
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
