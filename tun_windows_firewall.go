//go:build windows

package tun

import (
	"net"
	"os"
	"unsafe"

	"github.com/metacubex/sing-tun/internal/winsys"
)

// firewallEngine is the Windows Filtering Platform session that holds a strict
// route's filters. The session is dynamic: closing it removes every filter it
// added.
type firewallEngine interface {
	addSubLayer(subLayer *winsys.FWPM_SUBLAYER0) error
	addFilter(filter *winsys.FWPM_FILTER0) error
	close() error
}

// Replaced by tests, since opening a session and adding filters needs
// administrator rights.
var (
	openFirewallEngine   = openWindowsFirewallEngine
	lookupInterfaceIndex = func(name string) (uint32, error) {
		netInterface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return uint32(netInterface.Index), nil
	}
)

type windowsFirewallEngine struct {
	handle uintptr
}

func openWindowsFirewallEngine() (firewallEngine, error) {
	var handle uintptr
	session := &winsys.FWPM_SESSION0{Flags: winsys.FWPM_SESSION_FLAG_DYNAMIC}
	err := winsys.FwpmEngineOpen0(nil, winsys.RPC_C_AUTHN_DEFAULT, nil, session, unsafe.Pointer(&handle))
	if err != nil {
		return nil, os.NewSyscallError("FwpmEngineOpen0", err)
	}
	return &windowsFirewallEngine{handle: handle}, nil
}

func (e *windowsFirewallEngine) addSubLayer(subLayer *winsys.FWPM_SUBLAYER0) error {
	err := winsys.FwpmSubLayerAdd0(e.handle, subLayer, 0)
	if err != nil {
		return os.NewSyscallError("FwpmSubLayerAdd0", err)
	}
	return nil
}

func (e *windowsFirewallEngine) addFilter(filter *winsys.FWPM_FILTER0) error {
	var filterID uint64
	err := winsys.FwpmFilterAdd0(e.handle, filter, 0, &filterID)
	if err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}
	return nil
}

func (e *windowsFirewallEngine) close() error {
	return winsys.FwpmEngineClose0(e.handle)
}

func (t *NativeTun) closeFirewall() {
	if t.firewall == nil {
		return
	}
	t.firewall.close()
	t.firewall = nil
}
