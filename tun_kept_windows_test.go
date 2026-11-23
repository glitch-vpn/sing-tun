//go:build windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
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

// releaseLease ends a session the way NativeTun.Close does, minus the driver.
func releaseLease(lease *adapterLease) {
	(&NativeTun{adapter: lease.adapter, luid: lease.luid, kept: lease.kept}).releaseAdapter()
}

func useAdapterGone(t *testing.T, gone bool) {
	t.Helper()
	previous := adapterGone
	adapterGone = func(uint64) bool { return gone }
	t.Cleanup(func() { adapterGone = previous })
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
func TestLeaseOnAKeptAdapterCreatesNothing(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, freshAdapters)
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		lease, err := leaseAdapter("glitchvpn")
		require.NoError(t, err)
		require.Same(t, kept, lease.kept)
		require.Same(t, fake.created[0], lease.adapter)
		releaseLease(lease)
	}
	require.Len(t, fake.created, 1, "a session created an adapter beside the kept one")
	require.Equal(t, 3, fake.created[0].sessions)
	require.Zero(t, fake.created[0].closed)
}

// Without a kept adapter each session creates its own, and releasing it
// removes it.
func TestLeaseWithoutAKeptAdapterCreatesOne(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
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
func TestLeaseRefusesAnAdapterAnotherProcessHolds(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, func(int) (*fakeAdapter, error) { return nil, syscall.Errno(0x800700B7) })
	_, err := leaseAdapter("GlitchVPN")
	require.ErrorIs(t, err, ErrAdapterHeld)
	require.Empty(t, fake.created)
}

func TestLeaseOtherCreateErrorsAreNotTakenForAnotherHolder(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useFakeWintun(t, func(int) (*fakeAdapter, error) { return nil, errors.New("driver missing") })
	_, err := leaseAdapter("GlitchVPN")
	require.EqualError(t, err, "driver missing")
}

func TestLeaseClosesTheAdapterWhenItsSessionCannotStart(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, func(int) (*fakeAdapter, error) {
		return &fakeAdapter{sessionErrs: []error{errors.New("no ring")}}, nil
	})
	_, err := leaseAdapter("GlitchVPN")
	require.EqualError(t, err, "no ring")
	require.Equal(t, 1, fake.created[0].closed, "the handle of a failed session start stayed open")
}

// A kept adapter the user disabled or a network reset removed: the session
// start fails, the adapter is created again, within the same connect.
func TestLeaseCreatesAKeptAdapterAgainWhenItWasLost(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useAdapterGone(t, true)
	fake := useFakeWintun(t, func(n int) (*fakeAdapter, error) {
		if n == 0 {
			return &fakeAdapter{luid: 1, sessionErrs: []error{nil, errors.New("device gone")}}, nil
		}
		return &fakeAdapter{luid: 2}, nil
	})
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	first, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	releaseLease(first)
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
func TestLeaseDropsTheKeptAdapterThatCannotBeCreatedAgain(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useAdapterGone(t, true)
	fake := useFakeWintun(t, func(n int) (*fakeAdapter, error) {
		if n == 0 {
			return &fakeAdapter{sessionErrs: []error{errors.New("device gone")}}, nil
		}
		return nil, syscall.Errno(0x800700B7)
	})
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	_, err = leaseAdapter("GlitchVPN")
	require.ErrorIs(t, err, ErrAdapterHeld)
	require.False(t, kept.Usable())
	require.Nil(t, keptAdapterFor("GlitchVPN"))
	require.Equal(t, 1, fake.created[0].closed)
}

func TestClosingTheKeptAdapterRemovesItOnceAndForgetsTheName(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
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

func (f *fakeFlusher) FlushManagedRoutes(family winipcfg.AddressFamily) error {
	return f.flush("routes", family)
}

func (f *fakeFlusher) FlushManualIPAddresses(family winipcfg.AddressFamily) error {
	return f.flush("addresses", family)
}

func (f *fakeFlusher) FlushDNS(family winipcfg.AddressFamily) error { return f.flush("dns", family) }

func useFakeFlusher(t *testing.T, flusher *fakeFlusher) {
	adapterFlusher = func(uint64) addressFamilyFlusher { return flusher }
	t.Cleanup(func() { adapterFlusher = func(luid uint64) addressFamilyFlusher { return winipcfg.LUID(luid) } })
}

// Releasing a kept adapter leaves the device and takes every address, route
// and DNS server of both families off it.
func TestReleasingAKeptAdapterClearsBothFamiliesAndKeepsTheDevice(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	out := captureLog(t)
	flusher := &fakeFlusher{}
	useFakeFlusher(t, flusher)
	adapter := &fakeAdapter{luid: 5}
	(&NativeTun{adapter: adapter, luid: 5, kept: &KeptAdapter{}}).releaseAdapter()
	require.ElementsMatch(t, []string{"routes4", "addresses4", "dns4", "routes6", "addresses6", "dns6"}, flusher.flushed)
	require.Zero(t, adapter.closed, "a kept adapter was removed by a session's release")
	require.Contains(t, out.String(), "[tun] kept adapter cleared in ")
}

func TestAClearThatFailsIsLoggedAndNotReportedAsDone(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
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
func TestStrictRouteFindsTheTunnelByTheAdaptersLUID(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useFakeFirewall(t, -1)
	previous := lookupInterfaceIndex
	t.Cleanup(func() { lookupInterfaceIndex = previous })
	var asked uint64
	lookupInterfaceIndex = func(luid uint64) (uint32, error) { asked = luid; return 9, nil }
	require.NoError(t, strictRouteTun(ipv4Only(Options{})).configureFirewall())
	require.Equal(t, uint64(42), asked)
}

// Wintun hands back the failure of SwDeviceCreate as an HRESULT, which is not
// os.ErrExist: the Win32 code and its HRESULT form both mean the name is taken.
func TestAdapterExistsKnowsTheHRESULTForm(t *testing.T) {
	t.Parallel()
	require.False(t, errors.Is(syscall.Errno(0x800700B7), os.ErrExist), "the premise: the HRESULT does not match ErrExist")
	for _, err := range []error{
		syscall.Errno(183), syscall.Errno(0x800700B7),
		syscall.Errno(80), syscall.Errno(0x80070050),
		fmt.Errorf("wrapped: %w", syscall.Errno(0x800700B7)),
	} {
		require.True(t, adapterExists(err), "%v not taken for an existing adapter", err)
	}
	for _, err := range []error{
		nil, errors.New("driver missing"), syscall.Errno(5), syscall.Errno(0x80070005), syscall.Errno(0x80004005),
	} {
		require.False(t, adapterExists(err), "%v taken for an existing adapter", err)
	}
}

func TestKeepAdapterOnAHeldNameSaysSo(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useFakeWintun(t, func(int) (*fakeAdapter, error) { return nil, syscall.Errno(0x800700B7) })
	_, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.ErrorIs(t, err, ErrAdapterHeld)
	require.Nil(t, keptAdapterFor("GlitchVPN"))
}

// The kept adapter has one session at a time, and a refused second session
// leaves the first one's adapter alone.
func TestLeaseRefusesASecondSessionOnTheKeptAdapter(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, freshAdapters)
	_, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	first, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	_, err = leaseAdapter("GlitchVPN")
	require.Error(t, err)
	require.Len(t, fake.created, 1)
	require.Zero(t, fake.created[0].closed)
	(&NativeTun{adapter: first.adapter, luid: first.luid, kept: first.kept}).releaseAdapter()
	_, err = leaseAdapter("GlitchVPN")
	require.NoError(t, err, "the adapter stayed busy after its session was released")
}

// A session start that fails on an adapter Windows still lists is that
// session's failure: the device is left, and nothing is created.
func TestLeaseKeepsTheDeviceWhenTheSessionFailsOnAPresentAdapter(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useAdapterGone(t, false)
	fake := useFakeWintun(t, func(int) (*fakeAdapter, error) {
		return &fakeAdapter{sessionErrs: []error{nil, errors.New("ring in use")}}, nil
	})
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	first, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	(&NativeTun{adapter: first.adapter, luid: first.luid, kept: first.kept}).releaseAdapter()
	_, err = leaseAdapter("GlitchVPN")
	require.EqualError(t, err, "ring in use")
	require.Len(t, fake.created, 1)
	require.Zero(t, fake.created[0].closed, "a failed session start removed a device that is still there")
	require.True(t, kept.Usable())
}

// After Close the kept adapter is not created again by a late session.
func TestLeaseAfterCloseFailsAndCreatesNothing(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, freshAdapters)
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	require.NoError(t, kept.Close())
	_, err = kept.lease()
	require.ErrorIs(t, err, ErrAdapterClosed)
	_, err = leaseAdapter("GlitchVPN")
	require.NoError(t, err, "with the name forgotten the session creates its own")
	require.Len(t, fake.created, 2)
	require.Nil(t, keptAdapterFor("GlitchVPN"), "a closed kept adapter was registered again")
}

// A Tun still open when its kept adapter closes releases without touching the
// freed handle: the LUID was read when the session started.
func TestReleaseAfterTheKeptAdapterClosedDoesNotTouchItsHandle(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useFakeWintun(t, freshAdapters)
	flusher := &fakeFlusher{}
	useFakeFlusher(t, flusher)
	kept, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)
	lease, err := leaseAdapter("GlitchVPN")
	require.NoError(t, err)
	require.NoError(t, kept.Close())
	tun := &NativeTun{adapter: nil, luid: lease.luid, kept: lease.kept}
	require.NotPanics(t, tun.releaseAdapter)
	require.Len(t, flusher.flushed, 6)
}

// A kept adapter is cleared before configure() runs: what an earlier session
// whose clearing failed left must not reach the next one.
func TestAKeptAdapterIsClearedBeforeItIsConfigured(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	useFakeWintun(t, freshAdapters)
	flusher := &fakeFlusher{}
	useFakeFlusher(t, flusher)
	previousWait, previousEnd := sessionReadWaitEvent, endSession
	sessionReadWaitEvent = func(wintun.Session) windows.Handle { return 0 }
	endSession = func(wintun.Session) {}
	t.Cleanup(func() { sessionReadWaitEvent, endSession = previousWait, previousEnd })
	_, err := KeepAdapter("GlitchVPN", "Glitch VPN")
	require.NoError(t, err)

	var flushedBeforeConfigure int
	tun, err := startTun(Options{Name: "GlitchVPN"}, func(*NativeTun) error {
		flushedBeforeConfigure = len(flusher.flushed)
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, tun.kept)
	require.Equal(t, 6, flushedBeforeConfigure, "the adapter was not cleared of both families before configure ran")
}

// A configure that fails gives a kept adapter back cleared and idle, and a
// session's own adapter removed.
func TestAFailedConfigureReleasesTheAdapter(t *testing.T) { //nolint:paralleltest // replaces the package-level createAdapter, adapterGone, keptAdapters and the default log output
	fake := useFakeWintun(t, freshAdapters)
	flusher := &fakeFlusher{}
	useFakeFlusher(t, flusher)
	previousWait, previousEnd := sessionReadWaitEvent, endSession
	sessionReadWaitEvent = func(wintun.Session) windows.Handle { return 0 }
	ended := 0
	endSession = func(wintun.Session) { ended++ }
	t.Cleanup(func() { sessionReadWaitEvent, endSession = previousWait, previousEnd })

	_, err := startTun(Options{Name: "GlitchVPN"}, func(*NativeTun) error { return errors.New("no route") })
	require.EqualError(t, err, "no route")
	require.Equal(t, 1, ended)
	require.Equal(t, 1, fake.created[0].closed, "the session's own adapter stayed after a failed configure")

	kept, err := KeepAdapter("Other", "Glitch VPN")
	require.NoError(t, err)
	_, err = startTun(Options{Name: "Other"}, func(*NativeTun) error { return errors.New("no route") })
	require.EqualError(t, err, "no route")
	require.Zero(t, fake.created[1].closed)
	_, err = kept.lease()
	require.NoError(t, err, "the kept adapter stayed busy after a failed configure")
}
