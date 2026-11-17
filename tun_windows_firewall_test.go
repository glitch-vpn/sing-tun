//go:build windows

package tun

import (
	"errors"
	"net/netip"
	"testing"

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
