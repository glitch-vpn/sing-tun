//go:build windows

package tun

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	"github.com/metacubex/sing-tun/internal/wintun"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fakeAdapter is a Wintun adapter that counts what is done to it.
type fakeAdapter struct {
	luid        uint64
	sessions    int
	closed      int
	sessionErrs []error // consumed one per StartSession
}

func (a *fakeAdapter) LUID() uint64 { return a.luid }
func (a *fakeAdapter) Close() error { a.closed++; return nil }
func (a *fakeAdapter) StartSession(uint32) (wintun.Session, error) {
	a.sessions++
	if len(a.sessionErrs) > 0 {
		err := a.sessionErrs[0]
		a.sessionErrs = a.sessionErrs[1:]
		if err != nil {
			return wintun.Session{}, err
		}
	}
	return wintun.Session{}, nil
}

// fakeWintun replaces the creation of adapters and keeps every one it made.
type fakeWintun struct {
	created []*fakeAdapter
	next    func(n int) (*fakeAdapter, error)
}

func useFakeWintun(t *testing.T, next func(n int) (*fakeAdapter, error)) *fakeWintun {
	t.Helper()
	fake := &fakeWintun{next: next}
	createAdapter = func(name, tunnelType string, guid *windows.GUID) (adapterHandle, error) {
		adapter, err := fake.next(len(fake.created))
		if err != nil {
			return nil, err
		}
		fake.created = append(fake.created, adapter)
		return adapter, nil
	}
	t.Cleanup(func() {
		createAdapter = func(name, tunnelType string, guid *windows.GUID) (adapterHandle, error) {
			adapter, err := wintun.CreateAdapter(name, tunnelType, guid)
			if err != nil {
				return nil, err
			}
			return adapter, nil
		}
		keptAdaptersMu.Lock()
		keptAdapters = map[string]*KeptAdapter{}
		keptAdaptersMu.Unlock()
	})
	return fake
}

func freshAdapters(n int) (*fakeAdapter, error) { return &fakeAdapter{luid: uint64(100 + n)}, nil }

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &out
}

// Every session on a kept adapter is a session on the handle that created it:
// one create for the process, however many connects.
func TestLeaseOnAKeptAdapterCreatesNothing(t *testing.T) {
	fake := useFakeWintun(t, freshAdapters)
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		lease, err := leaseAdapter("glitchvpn")
		require.NoError(t, err)
		require.Same(t, kept, lease.kept)
		require.Same(t, fake.created[0], lease.adapter)
	}
	require.Len(t, fake.created, 1, "a session created an adapter beside the kept one")
	require.Equal(t, 3, fake.created[0].sessions)
	require.Zero(t, fake.created[0].closed)
}

// Without a kept adapter each session creates its own, and releasing it
// removes it.
func TestLeaseWithoutAKeptAdapterCreatesOne(t *testing.T) {
	fake := useFakeWintun(t, freshAdapters)
	lease, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	require.Nil(t, lease.kept)
	require.Len(t, fake.created, 1)
	(&NativeTun{adapter: lease.adapter, kept: lease.kept}).releaseAdapter()
	require.Equal(t, 1, fake.created[0].closed)
}

// A name another process holds is refused, not opened: a session on its
// adapter would lose it when that process goes.
func TestLeaseRefusesAnAdapterAnotherProcessHolds(t *testing.T) {
	fake := useFakeWintun(t, func(int) (*fakeAdapter, error) { return nil, windows.ERROR_ALREADY_EXISTS })
	_, err := leaseAdapter("GlitchVPN")
	require.ErrorIs(t, err, ErrAdapterHeld)
	require.Empty(t, fake.created)
}

func TestLeaseOtherCreateErrorsAreNotTakenForAnotherHolder(t *testing.T) {
	useFakeWintun(t, func(int) (*fakeAdapter, error) { return nil, errors.New("driver missing") })
	_, err := leaseAdapter("GlitchVPN")
	require.EqualError(t, err, "driver missing")
}

func TestLeaseClosesTheAdapterWhenItsSessionCannotStart(t *testing.T) {
	fake := useFakeWintun(t, func(int) (*fakeAdapter, error) {
		return &fakeAdapter{sessionErrs: []error{errors.New("no ring")}}, nil
	})
	_, err := leaseAdapter("GlitchVPN")
	require.EqualError(t, err, "no ring")
	require.Equal(t, 1, fake.created[0].closed, "the handle of a failed session start stayed open")
}

// A kept adapter the user disabled or a network reset removed: the session
// start fails, the adapter is created again, within the same connect.
func TestLeaseCreatesAKeptAdapterAgainWhenItWasLost(t *testing.T) {
	fake := useFakeWintun(t, func(n int) (*fakeAdapter, error) {
		if n == 0 {
			return &fakeAdapter{luid: 1, sessionErrs: []error{nil, errors.New("device gone")}}, nil
		}
		return &fakeAdapter{luid: 2}, nil
	})
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	_, err = leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	lease, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	require.Same(t, kept, lease.kept)
	require.Len(t, fake.created, 2)
	require.Equal(t, 1, fake.created[0].closed, "the lost adapter's handle stayed open")
	require.Same(t, fake.created[1], lease.adapter)
	require.True(t, kept.Usable())
}

// When it cannot be created again the mark is dropped, and the connect goes on
// to the session's own create, which is refused if another process took the
// name.
func TestLeaseDropsTheKeptAdapterThatCannotBeCreatedAgain(t *testing.T) {
	fake := useFakeWintun(t, func(n int) (*fakeAdapter, error) {
		if n == 0 {
			return &fakeAdapter{sessionErrs: []error{errors.New("device gone")}}, nil
		}
		return nil, windows.ERROR_ALREADY_EXISTS
	})
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	_, err = leaseAdapter("GlitchVPN")
	require.ErrorIs(t, err, ErrAdapterHeld)
	require.False(t, kept.Usable())
	require.Nil(t, keptAdapterFor("GlitchVPN"))
	require.Equal(t, 1, fake.created[0].closed)
}

func TestClosingTheKeptAdapterRemovesItOnceAndForgetsTheName(t *testing.T) {
	fake := useFakeWintun(t, freshAdapters)
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	require.NoError(t, kept.Close())
	require.NoError(t, kept.Close())
	require.Equal(t, 1, fake.created[0].closed)
	require.Nil(t, keptAdapterFor("GlitchVPN"))
}

type fakeFlusher struct {
	failing map[string]bool // "routes4", "dns6", ...
	flushed []string
}

func (f *fakeFlusher) flush(what string, family winipcfg.AddressFamily) error {
	suffix := "4"
	if family == winipcfg.AddressFamily(windows.AF_INET6) {
		suffix = "6"
	}
	f.flushed = append(f.flushed, what+suffix)
	if f.failing[what+suffix] {
		return errors.New("access denied")
	}
	return nil
}

func (f *fakeFlusher) FlushRoutes(family winipcfg.AddressFamily) error {
	return f.flush("routes", family)
}

func (f *fakeFlusher) FlushIPAddresses(family winipcfg.AddressFamily) error {
	return f.flush("addresses", family)
}

func (f *fakeFlusher) FlushDNS(family winipcfg.AddressFamily) error { return f.flush("dns", family) }

func useFakeFlusher(t *testing.T, flusher *fakeFlusher) {
	adapterFlusher = func(uint64) addressFamilyFlusher { return flusher }
	t.Cleanup(func() { adapterFlusher = func(luid uint64) addressFamilyFlusher { return winipcfg.LUID(luid) } })
}

// Releasing a kept adapter leaves the device and takes every address, route
// and DNS server of both families off it.
func TestReleasingAKeptAdapterClearsBothFamiliesAndKeepsTheDevice(t *testing.T) {
	out := captureLog(t)
	flusher := &fakeFlusher{}
	useFakeFlusher(t, flusher)
	adapter := &fakeAdapter{luid: 5}
	(&NativeTun{adapter: adapter, kept: &KeptAdapter{}}).releaseAdapter()
	require.ElementsMatch(t, []string{"routes4", "addresses4", "dns4", "routes6", "addresses6", "dns6"}, flusher.flushed)
	require.Zero(t, adapter.closed, "a kept adapter was removed by a session's release")
	require.Contains(t, out.String(), "[tun] kept adapter cleared in ")
}

func TestAClearThatFailsIsLoggedAndNotReportedAsDone(t *testing.T) {
	out := captureLog(t)
	flusher := &fakeFlusher{failing: map[string]bool{"dns6": true, "routes4": true}}
	useFakeFlusher(t, flusher)
	(&NativeTun{adapter: &fakeAdapter{}, kept: &KeptAdapter{}}).releaseAdapter()
	logged := out.String()
	require.Contains(t, logged, "ipv6 dns not cleared: access denied")
	require.Contains(t, logged, "ipv4 routes not cleared: access denied")
	require.False(t, strings.Contains(logged, "kept adapter cleared in"), "reported cleared after a failure:\n%s", logged)
	require.Len(t, flusher.flushed, 6, "a failure stopped the rest of the clearing")
}

// The strict route's filters name the tunnel's interface by the adapter's
// LUID: its connection name is the user's to change.
func TestStrictRouteFindsTheTunnelByTheAdaptersLUID(t *testing.T) {
	useFakeFirewall(t, -1)
	previous := lookupInterfaceIndex
	t.Cleanup(func() { lookupInterfaceIndex = previous })
	var asked uint64
	lookupInterfaceIndex = func(luid uint64) (uint32, error) { asked = luid; return 9, nil }
	require.NoError(t, strictRouteTun(ipv4Only(Options{})).configureFirewall())
	require.Equal(t, uint64(42), asked)
}
