package tun

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"sync"
	"time"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	"github.com/metacubex/sing-tun/internal/wintun"

	"golang.org/x/sys/windows"
)

// adapterHandle is a Wintun adapter: *wintun.Adapter, or a fake in the tests.
type adapterHandle interface {
	LUID() uint64
	Close() error
	StartSession(capacity uint32) (wintun.Session, error)
}

// The tests' seam over Wintun's DLL. It returns a nil interface on error.
var createAdapter = func(name, tunnelType string, guid *windows.GUID) (adapterHandle, error) {
	adapter, err := wintun.CreateAdapter(name, tunnelType, guid)
	if err != nil {
		return nil, err
	}
	return adapter, nil
}

// sessionRingCapacity is the size of a session's rings.
const sessionRingCapacity = 0x800000

// ErrAdapterHeld is what a connect gets when the adapter's name is taken by an
// adapter this process did not create: another core, the GlitchVpnCore service
// or another running instance, owns it, and a session on it would lose the
// adapter when that owner goes.
var ErrAdapterHeld = errors.New("the adapter is held by another process: stop the other Glitch VPN core (the GlitchVpnCore service or another running instance)")

// adapterExists is whether a create failed because the adapter's instance is
// already there. Wintun returns the failure of SwDeviceCreate as it got it, an
// HRESULT in the Win32 facility (0x8007xxxx) rather than the Win32 code, and
// errors.Is(err, os.ErrExist) knows only the code.
func adapterExists(err error) bool {
	if errors.Is(err, os.ErrExist) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	code := uint32(errno)
	if code>>16 == 0x8007 {
		code &= 0xFFFF
	}
	return code == uint32(windows.ERROR_ALREADY_EXISTS) || code == uint32(windows.ERROR_FILE_EXISTS)
}

// The tests' seam over whether an interface is still there.
var adapterGone = func(luid uint64) bool {
	row, err := winipcfg.LUID(luid).Interface()
	return err != nil || row.OperStatus == winipcfg.IfOperStatusNotPresent
}

// ErrAdapterBusy is what a second session on the kept adapter gets while one
// runs: it has one session at a time.
var ErrAdapterBusy = errors.New("a session is already running on the kept adapter")

// ErrAdapterClosed is what a session on a closed kept adapter gets.
var ErrAdapterClosed = errors.New("the kept adapter is closed")

// keptAdapters maps an adapter's name, folded to lower case as Windows
// compares it, to the adapter this process keeps under it.
var (
	keptAdaptersMu sync.Mutex
	keptAdapters   = map[string]*KeptAdapter{}
)

func keptAdapterKey(name string) string { return strings.ToLower(name) }

func keptAdapterFor(name string) *KeptAdapter {
	keptAdaptersMu.Lock()
	defer keptAdaptersMu.Unlock()
	return keptAdapters[keptAdapterKey(name)]
}

// KeptAdapter is a Wintun adapter created once and held by its creating
// handle: Wintun's software device lives as long as that handle is open, and
// creating or removing one costs seconds. While it is kept, New for its name
// starts a session on that handle, and a Tun's Close ends the session and
// clears the addresses, routes and DNS servers it set, leaving the adapter
// disconnected; the device goes only with Close of the KeptAdapter.
//
// New never runs a session on an adapter it did not create: one of the same
// name that another process holds is refused with ErrAdapterHeld. A kept
// adapter has one session at a time.
type KeptAdapter struct {
	name       string
	tunnelType string
	mu         sync.Mutex
	adapter    adapterHandle // nil once dropped or closed
	active     bool          // a session runs on it
	closed     bool
}

// KeepAdapter creates the adapter name, described as "<tunnelType> Tunnel",
// with the GUID New derives from the name. It fails when an adapter of that
// name exists, whoever created it, and then nothing is kept.
func KeepAdapter(name, tunnelType string) (*KeptAdapter, error) {
	k := &KeptAdapter{name: name, tunnelType: tunnelType}
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.createLocked("kept adapter created"); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *KeptAdapter) createLocked(step string) error {
	mark := time.Now()
	if k.closed {
		return ErrAdapterClosed
	}
	adapter, err := createAdapter(k.name, k.tunnelType, generateGUIDByDeviceName(k.name))
	if err != nil {
		if adapterExists(err) {
			return fmt.Errorf("create adapter: %w", ErrAdapterHeld)
		}
		return err
	}
	k.adapter = adapter
	keptAdaptersMu.Lock()
	keptAdapters[keptAdapterKey(k.name)] = k
	keptAdaptersMu.Unlock()
	logStep(step, &mark)
	return nil
}

// Usable is whether sessions still run on this adapter: false once it was
// lost and could not be created again, or closed.
func (k *KeptAdapter) Usable() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.adapter != nil
}

// dropLocked forgets the adapter and closes its handle, which removes the
// device if there is still one.
func (k *KeptAdapter) dropLocked() error {
	if k.adapter == nil {
		return nil
	}
	keptAdaptersMu.Lock()
	if keptAdapters[keptAdapterKey(k.name)] == k {
		delete(keptAdapters, keptAdapterKey(k.name))
	}
	keptAdaptersMu.Unlock()
	err := k.adapter.Close()
	k.adapter = nil
	return err
}

// Close removes the device and ends the keeping for good: a session started
// after it fails. A Tun on the adapter should be closed first; one that is not
// finds its adapter gone and clears nothing. It is safe to call more than once.
func (k *KeptAdapter) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closed = true
	if k.adapter == nil {
		return nil
	}
	mark := time.Now()
	err := k.dropLocked()
	logStep("kept adapter removed", &mark)
	return err
}

// adapterLease is an adapter with a session started on it.
type adapterLease struct {
	adapter adapterHandle
	session wintun.Session
	luid    uint64       // read while the handle is open: a Close of the kept adapter frees it
	kept    *KeptAdapter // nil when the adapter is the session's own
}

// leaseAdapter starts a session on the adapter name for one Tun. The kept
// adapter takes it directly; one that is gone (uninstalled, or lost to a
// network reset) is created again, once, and failing that is dropped, so the
// next step is a create of the session's own. A session that fails on a kept
// adapter that is still there fails the connect. A name taken by an adapter
// this process did not create is refused.
func leaseAdapter(name string) (*adapterLease, error) {
	mark := time.Now()
	if k := keptAdapterFor(name); k != nil {
		lease, err := k.lease()
		if err == nil {
			logStep("kept adapter session started", &mark)
			return lease, nil
		}
		if k.Usable() {
			return nil, err
		}
		log.Printf("[tun] kept adapter unusable, creating the session's own: %v", err)
		mark = time.Now()
	}
	adapter, err := createAdapter(name, TunnelType, generateGUIDByDeviceName(name))
	if err != nil {
		if adapterExists(err) {
			return nil, fmt.Errorf("create adapter: %w", ErrAdapterHeld)
		}
		return nil, err
	}
	logStep("wintun adapter created", &mark)
	session, err := adapter.StartSession(sessionRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, err
	}
	logStep("wintun session started", &mark)
	return &adapterLease{adapter: adapter, session: session, luid: adapter.LUID()}, nil
}

// lease starts the session on the held handle. A start that fails on an
// adapter Windows still lists is that session's failure and leaves the device
// alone; one that fails because the adapter is gone creates it again.
func (k *KeptAdapter) lease() (*adapterLease, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, ErrAdapterClosed
	}
	if k.active {
		return nil, ErrAdapterBusy
	}
	if k.adapter != nil {
		luid := k.adapter.LUID()
		session, err := k.adapter.StartSession(sessionRingCapacity)
		if err == nil {
			k.active = true
			return &adapterLease{adapter: k.adapter, session: session, luid: luid, kept: k}, nil
		}
		if !adapterGone(luid) {
			return nil, err
		}
		log.Printf("[tun] kept adapter is gone: %v", err)
		k.dropLocked()
	}
	if err := k.createLocked("kept adapter created again"); err != nil {
		return nil, err
	}
	luid := k.adapter.LUID()
	session, err := k.adapter.StartSession(sessionRingCapacity)
	if err != nil {
		k.dropLocked()
		return nil, err
	}
	k.active = true
	return &adapterLease{adapter: k.adapter, session: session, luid: luid, kept: k}, nil
}

// releaseAdapter gives the adapter back once the session has ended: a kept
// one is cleared and stays, the session's own is removed.
func (t *NativeTun) releaseAdapter() {
	if t.kept != nil {
		t.clearKeptAdapter()
		t.kept.mu.Lock()
		t.kept.active = false
		t.kept.mu.Unlock()
		return
	}
	mark := time.Now()
	t.adapter.Close()
	logStep("wintun adapter closed", &mark)
}

// adapterFlusher is the tests' seam over the adapter's configuration.
var adapterFlusher = func(luid uint64) addressFamilyFlusher { return winipcfg.LUID(luid) }

// addressFamilyFlusher is winipcfg.LUID, or a fake in the tests.
type addressFamilyFlusher interface {
	FlushManagedRoutes(family winipcfg.AddressFamily) error
	FlushManualIPAddresses(family winipcfg.AddressFamily) error
	FlushDNS(family winipcfg.AddressFamily) error
}

// clearKeptAdapter removes the routes, addresses and DNS servers set on the
// adapter by hand, which removing the device would have taken and a kept one
// keeps. What Windows gives an interface (its multicast routes, an IPv6
// link-local address) is left. It logs each that stays, and the step only when
// none did.
func (t *NativeTun) clearKeptAdapter() {
	mark := time.Now()
	if clearAdapter(adapterFlusher(t.luid)) {
		logStep("kept adapter cleared", &mark)
	}
}

func clearAdapter(flusher addressFamilyFlusher) bool {
	cleared := true
	for _, family := range []struct {
		name string
		id   winipcfg.AddressFamily
	}{
		{"ipv4", winipcfg.AddressFamily(windows.AF_INET)},
		{"ipv6", winipcfg.AddressFamily(windows.AF_INET6)},
	} {
		for _, step := range []struct {
			what  string
			flush func(winipcfg.AddressFamily) error
		}{
			{"routes", flusher.FlushManagedRoutes},
			{"addresses", flusher.FlushManualIPAddresses},
			{"dns", flusher.FlushDNS},
		} {
			if err := step.flush(family.id); err != nil {
				log.Printf("[tun] kept adapter: %s %s not cleared: %v", family.name, step.what, err)
				cleared = false
			}
		}
	}
	return cleared
}
