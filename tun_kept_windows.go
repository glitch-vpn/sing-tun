package tun

import (
	"strings"
	"sync"
	"time"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	"github.com/metacubex/sing-tun/internal/wintun"

	"golang.org/x/sys/windows"
)

// keptAdapters holds the names of the adapters a KeptAdapter keeps, folded to
// lower case as Windows compares them.
var keptAdapters sync.Map

func keptAdapterKey(name string) string { return strings.ToLower(name) }

func isKeptAdapter(name string) bool {
	_, ok := keptAdapters.Load(keptAdapterKey(name))
	return ok
}

// KeptAdapter is a Wintun adapter created once and held by its creating
// handle: Wintun's software device lives as long as that handle is open, and
// creating or removing one costs seconds. While it is kept, New for its name
// opens it and starts a session, and a Tun's Close ends the session and
// clears the addresses, routes and DNS servers it set, leaving the adapter
// disconnected; the device goes only with Close of the KeptAdapter.
type KeptAdapter struct {
	name    string
	adapter *wintun.Adapter
	once    sync.Once
}

// KeepAdapter creates the adapter name, described as "<tunnelType> Tunnel",
// with the GUID New derives from the name. It fails when an adapter of that
// name exists, whoever created it, and then nothing is kept.
func KeepAdapter(name, tunnelType string) (*KeptAdapter, error) {
	mark := time.Now()
	adapter, err := wintun.CreateAdapter(name, tunnelType, generateGUIDByDeviceName(name))
	if err != nil {
		return nil, err
	}
	keptAdapters.Store(keptAdapterKey(name), struct{}{})
	logStep("kept adapter created", &mark)
	return &KeptAdapter{name: name, adapter: adapter}, nil
}

// Close removes the device. A Tun opened on it must be closed first. It is
// safe to call more than once.
func (k *KeptAdapter) Close() error {
	var err error
	k.once.Do(func() {
		keptAdapters.Delete(keptAdapterKey(k.name))
		mark := time.Now()
		err = k.adapter.Close()
		logStep("kept adapter removed", &mark)
	})
	return err
}

// clearKeptAdapter removes every address, route and DNS server on the
// adapter: removing the device would have taken them, and a kept one stays.
func (t *NativeTun) clearKeptAdapter() {
	luid := winipcfg.LUID(t.adapter.LUID())
	for _, family := range []winipcfg.AddressFamily{winipcfg.AddressFamily(windows.AF_INET), winipcfg.AddressFamily(windows.AF_INET6)} {
		luid.FlushRoutes(family)
		luid.FlushIPAddresses(family)
		luid.FlushDNS(family)
	}
}
