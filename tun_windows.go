package tun

import (
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/windnsapi"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	"github.com/metacubex/sing-tun/internal/winsys"
	"github.com/metacubex/sing-tun/internal/wintun"

	"golang.org/x/sys/windows"
)

var (
	TunnelType              = "sing-tun"
	ipv6AllRoutersMulticast = winsys.FWP_BYTE_ARRAY16{ByteArray16: [16]uint8{0xff, 0x02, 15: 0x02}}

	// Package level, since a filter condition holds their address as a uintptr.
	ipv6LoopbackPrefix    = winsys.FWP_V6_ADDR_AND_MASK{Addr: [16]uint8{15: 0x01}, PrefixLength: 128}
	ipv6LinkLocalPrefix   = winsys.FWP_V6_ADDR_AND_MASK{Addr: [16]uint8{0xfe, 0x80}, PrefixLength: 10}
	ipv6UniqueLocalPrefix = winsys.FWP_V6_ADDR_AND_MASK{Addr: [16]uint8{0xfc}, PrefixLength: 7}
	ipv6MulticastPrefix   = winsys.FWP_V6_ADDR_AND_MASK{Addr: [16]uint8{0xff}, PrefixLength: 8}
)

type NativeTun struct {
	adapter   adapterHandle
	options   Options
	session   wintun.Session
	readWait  windows.Handle
	rate      rateJuggler
	running   sync.WaitGroup
	closeOnce sync.Once
	close     atomic.Int32
	firewall  firewallEngine
	// kept: the adapter this process keeps, which Close leaves in place after
	// clearing what the session set on it. Otherwise the adapter is the
	// session's own and Close removes it.
	kept *KeptAdapter
	// luid is read when the session starts: a closed KeptAdapter frees the
	// handle the Tun's adapter points to.
	luid uint64
}

// logStep writes how long the step since mark took and starts the next one.
// The lines carry no address or name, and reach whatever the process
// directs the standard logger to.
func logStep(step string, mark *time.Time) {
	now := time.Now()
	log.Printf("[tun] %s in %dms", step, now.Sub(*mark).Milliseconds())
	*mark = now
}

func New(options Options) (WinTun, error) {
	return startTun(options, (*NativeTun).configure)
}

// The tests' seams over a Wintun session, which needs the driver.
var (
	sessionReadWaitEvent = func(session wintun.Session) windows.Handle { return session.ReadWaitEvent() }
	endSession           = func(session wintun.Session) { session.End() }
)

// startTun starts a session on the adapter and sets the Tun up with configure.
func startTun(options Options, configure func(*NativeTun) error) (*NativeTun, error) {
	if options.FileDescriptor != 0 {
		return nil, os.ErrInvalid
	}
	lease, err := leaseAdapter(options.Name)
	if err != nil {
		return nil, err
	}
	nativeTun := &NativeTun{
		adapter:  lease.adapter,
		options:  options,
		session:  lease.session,
		readWait: sessionReadWaitEvent(lease.session),
		kept:     lease.kept,
		luid:     lease.luid,
	}
	if nativeTun.kept != nil {
		// Whatever an earlier session left is not this session's: an IPv6
		// resolver must not outlive the IPv6 it served.
		nativeTun.clearKeptAdapter()
	}
	err = configure(nativeTun)
	if err != nil {
		endSession(lease.session)
		nativeTun.releaseAdapter()
		return nil, err
	}
	return nativeTun, nil
}

func (t *NativeTun) configure() error {
	mark := time.Now()
	luid := winipcfg.LUID(t.luid)
	if len(t.options.Inet4Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), t.options.Inet4Address)
		if err != nil {
			return E.Cause(err, "set ipv4 address")
		}
		logStep("ipv4 address set", &mark)
		if t.options.DNSModeOrDefault() != DNSModeDisabled {
			dnsServers, err := t.options.Inet4DNSAddress()
			if err != nil {
				return err
			}
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), dnsServers, nil)
			if err != nil {
				return E.Cause(err, "set ipv4 dns")
			}
			logStep("ipv4 dns set", &mark)
		} else {
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), nil, nil)
			if err != nil {
				return E.Cause(err, "set ipv4 dns")
			}
			logStep("ipv4 dns cleared", &mark)
		}
	}
	if len(t.options.Inet6Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), t.options.Inet6Address)
		if err != nil {
			return E.Cause(err, "set ipv6 address")
		}
		logStep("ipv6 address set", &mark)
		if t.options.DNSModeOrDefault() != DNSModeDisabled {
			dnsServers, err := t.options.Inet6DNSAddress()
			if err != nil {
				return err
			}
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), dnsServers, nil)
			if err != nil {
				return E.Cause(err, "set ipv6 dns")
			}
			logStep("ipv6 dns set", &mark)
		} else {
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), nil, nil)
			if err != nil {
				return E.Cause(err, "set ipv6 dns")
			}
			logStep("ipv6 dns cleared", &mark)
		}
	}
	if len(t.options.Inet4Address) > 0 || len(t.options.Inet6Address) > 0 {
		if luid.DisableDNSRegistration() == nil {
			logStep("dns registration disabled", &mark)
		}
	}
	if t.options.AutoRoute {
		gateway4, gateway6 := t.options.Inet4GatewayAddr(), t.options.Inet6GatewayAddr()
		routeRanges, err := t.options.BuildAutoRouteRanges(false)
		if err != nil {
			return err
		}
		err = addRoutes(routeRanges, func(routeRange netip.Prefix) error {
			if routeRange.Addr().Is4() {
				return luid.AddRoute(routeRange, gateway4, 0)
			}
			return luid.AddRoute(routeRange, gateway6, 0)
		})
		if err != nil {
			return err
		}
		logStep("routes added", &mark)
		err = windnsapi.FlushResolverCache()
		if err != nil {
			return err
		}
		logStep("resolver cache flushed", &mark)
	}
	if len(t.options.Inet4Address) > 0 {
		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inetIf.UseAutomaticMetric = false
			inetIf.Metric = 0
		}
		err = inetIf.Set()
		if err != nil {
			return E.Cause(err, "set ipv4 options")
		}
		logStep("ipv4 interface options set", &mark)
	}
	if len(t.options.Inet6Address) > 0 {
		inet6If, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}
		inet6If.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inet6If.DadTransmits = 0
		inet6If.ManagedAddressConfigurationSupported = false
		inet6If.OtherStatefulConfigurationSupported = false
		inet6If.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inet6If.UseAutomaticMetric = false
			inet6If.Metric = 0
		}
		err = inet6If.Set()
		if err != nil {
			return E.Cause(err, "set ipv6 options")
		}
		logStep("ipv6 interface options set", &mark)
	}

	if t.options.AutoRoute && t.options.StrictRoute {
		err := t.configureFirewall()
		if err != nil {
			return err
		}
		logStep("strict route filters installed", &mark)
	}

	return nil
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.rate.current.Load() >= spinloopRateThreshold && uint64(start-t.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
	for {
		if t.close.Load() == 1 {
			return 0, os.ErrClosed
		}
		var packet []byte
		packet, err = t.session.ReceivePacket()
		switch err {
		case nil:
			n = copy(p, packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(n))
			return
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return 0, errors.New("send ring corrupt")
		}
		return 0, fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) ReadPacket() ([]byte, func(), error) {
	t.running.Add(1)
retry:
	if t.close.Load() == 1 {
		t.running.Done()
		return nil, nil, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.rate.current.Load() >= spinloopRateThreshold && uint64(start-t.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
	for {
		if t.close.Load() == 1 {
			t.running.Done()
			return nil, nil, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			t.rate.update(uint64(packetSize))
			return packet, func() {
				t.session.ReleaseReceivePacket(packet)
				t.running.Done()
			}, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			t.running.Done()
			return nil, nil, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			t.running.Done()
			return nil, nil, errors.New("send ring corrupt")
		}
		t.running.Done()
		return nil, nil, fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) ReadFunc(block func(b []byte)) error {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if t.close.Load() == 1 {
		return os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.rate.current.Load() >= spinloopRateThreshold && uint64(start-t.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
	for {
		if t.close.Load() == 1 {
			return os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			block(packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(packetSize))
			return nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return errors.New("send ring corrupt")
		}
		return fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	t.rate.update(uint64(len(p)))
	packet, err := t.session.AllocateSendPacket(len(p))
	copy(packet, p)
	if err == nil {
		t.session.SendPacket(packet)
		return len(p), nil
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("write failed: %w", err)
}

func (t *NativeTun) write(packetElementList [][]byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	var packetSize int
	for _, packetElement := range packetElementList {
		packetSize += len(packetElement)
	}
	t.rate.update(uint64(packetSize))
	packet, err := t.session.AllocateSendPacket(packetSize)
	if err == nil {
		var index int
		for _, packetElement := range packetElementList {
			index += copy(packet[index:], packetElement)
		}
		t.session.SendPacket(packet)
		return
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("write failed: %w", err)
}

func (t *NativeTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		mark := time.Now()
		t.close.Store(1)
		windows.SetEvent(t.readWait)
		t.running.Wait()
		logStep("wintun readers stopped", &mark)
		endSession(t.session)
		logStep("wintun session ended", &mark)
		t.releaseAdapter()
		mark = time.Now()
		if t.firewall != nil {
			t.closeFirewall()
			logStep("strict route filters removed", &mark)
		}
		if t.options.AutoRoute {
			windnsapi.FlushResolverCache()
			logStep("resolver cache flushed", &mark)
		}
	})
	return err
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

type rateJuggler struct {
	current       atomic.Uint64
	nextByteCount atomic.Uint64
	nextStartTime atomic.Int64
	changing      atomic.Int32
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := rate.nextByteCount.Add(packetLen)
	period := uint64(now - rate.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		if !rate.changing.CompareAndSwap(0, 1) {
			return
		}
		rate.nextStartTime.Store(now)
		rate.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		rate.nextByteCount.Store(0)
		rate.changing.Store(0)
	}
}

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

// configureFirewall closes the session on a failure: it holds machine-wide
// blocks until it is closed.
func (t *NativeTun) configureFirewall() error {
	err := t.configureStrictRoute()
	if err != nil {
		t.closeFirewall()
	}
	return err
}

func (t *NativeTun) configureStrictRoute() error {
	engine, err := openFirewallEngine()
	if err != nil {
		return err
	}
	t.firewall = engine

	subLayerKey, err := windows.GenerateGUID()
	if err != nil {
		return os.NewSyscallError("CoCreateGuid", err)
	}

	subLayer := winsys.FWPM_SUBLAYER0{}
	subLayer.SubLayerKey = subLayerKey
	subLayer.DisplayData = winsys.CreateDisplayData(TunnelType, "auto-route rules")
	subLayer.Weight = math.MaxUint16
	err = engine.addSubLayer(&subLayer)
	if err != nil {
		return err
	}

	processAppID, err := winsys.GetCurrentProcessAppID()
	if err != nil {
		return err
	}
	defer winsys.FwpmFreeMemory0(unsafe.Pointer(&processAppID))

	permitCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
	permitCondition[0].FieldKey = winsys.FWPM_CONDITION_ALE_APP_ID
	permitCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
	permitCondition[0].ConditionValue.Type = winsys.FWP_BYTE_BLOB_TYPE
	permitCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(processAppID))

	permitFilter4 := winsys.FWPM_FILTER0{}
	permitFilter4.FilterCondition = &permitCondition[0]
	permitFilter4.NumFilterConditions = 1
	permitFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "protect ipv4")
	permitFilter4.SubLayerKey = subLayerKey
	permitFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	permitFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
	permitFilter4.Weight.Type = winsys.FWP_UINT8
	permitFilter4.Weight.Value = uintptr(13)
	permitFilter4.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	err = engine.addFilter(&permitFilter4)
	if err != nil {
		return err
	}

	permitFilter6 := winsys.FWPM_FILTER0{}
	permitFilter6.FilterCondition = &permitCondition[0]
	permitFilter6.NumFilterConditions = 1
	permitFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "protect ipv6")
	permitFilter6.SubLayerKey = subLayerKey
	permitFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
	permitFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
	permitFilter6.Weight.Type = winsys.FWP_UINT8
	permitFilter6.Weight.Value = uintptr(15)
	permitFilter6.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	err = engine.addFilter(&permitFilter6)
	if err != nil {
		return err
	}

	/*if len(t.options.Inet4Address) == 0 {
		blockFilter := winsys.FWPM_FILTER0{}
		blockFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv4")
		blockFilter.SubLayerKey = subLayerKey
		blockFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		blockFilter.Action.Type = winsys.FWP_ACTION_BLOCK
		blockFilter.Weight.Type = winsys.FWP_UINT8
		blockFilter.Weight.Value = uintptr(12)
		err = engine.addFilter(&blockFilter)
		if err != nil {
			return err
		}
	}*/

	if len(t.options.Inet6Address) == 0 {
		ndpCondition := make([]winsys.FWPM_FILTER_CONDITION0, 4)
		ndpCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_PROTOCOL
		ndpCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
		ndpCondition[0].ConditionValue.Type = winsys.FWP_UINT8
		ndpCondition[0].ConditionValue.Value = uintptr(winsys.IPPROTO_ICMPV6)
		ndpCondition[1].FieldKey = winsys.FWPM_CONDITION_ICMP_TYPE
		ndpCondition[1].MatchType = winsys.FWP_MATCH_EQUAL
		ndpCondition[1].ConditionValue.Type = winsys.FWP_UINT16
		ndpCondition[2].FieldKey = winsys.FWPM_CONDITION_ICMP_CODE
		ndpCondition[2].MatchType = winsys.FWP_MATCH_EQUAL
		ndpCondition[2].ConditionValue.Type = winsys.FWP_UINT16
		ndpCondition[2].ConditionValue.Value = 0
		ndpCondition[3].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS
		ndpCondition[3].MatchType = winsys.FWP_MATCH_EQUAL
		ndpCondition[3].ConditionValue.Type = winsys.FWP_BYTE_ARRAY16_TYPE
		ndpCondition[3].ConditionValue.Value = uintptr(unsafe.Pointer(&ipv6AllRoutersMulticast))
		for _, ndpMessage := range []struct {
			name          string
			icmpType      uint16
			numConditions uint32
		}{
			{"router solicitation", 133, 4},
			{"neighbor solicitation", 135, 3},
			{"neighbor advertisement", 136, 3},
		} {
			ndpCondition[1].ConditionValue.Value = uintptr(ndpMessage.icmpType)
			ndpFilter := winsys.FWPM_FILTER0{}
			ndpFilter.FilterCondition = &ndpCondition[0]
			ndpFilter.NumFilterConditions = ndpMessage.numConditions
			ndpFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv6 "+ndpMessage.name)
			ndpFilter.SubLayerKey = subLayerKey
			ndpFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
			ndpFilter.Action.Type = winsys.FWP_ACTION_PERMIT
			ndpFilter.Weight.Type = winsys.FWP_UINT8
			ndpFilter.Weight.Value = uintptr(13)
			err = engine.addFilter(&ndpFilter)
			if err != nil {
				return err
			}
		}

		permitPrefixes := []struct {
			name   string
			prefix *winsys.FWP_V6_ADDR_AND_MASK
		}{{"loopback", &ipv6LoopbackPrefix}}
		if t.options.StrictRouteLocalNetworksDirect {
			permitPrefixes = append(permitPrefixes,
				struct {
					name   string
					prefix *winsys.FWP_V6_ADDR_AND_MASK
				}{"link-local", &ipv6LinkLocalPrefix},
				struct {
					name   string
					prefix *winsys.FWP_V6_ADDR_AND_MASK
				}{"unique local", &ipv6UniqueLocalPrefix},
				struct {
					name   string
					prefix *winsys.FWP_V6_ADDR_AND_MASK
				}{"multicast", &ipv6MulticastPrefix},
			)
		}
		for _, permit := range permitPrefixes {
			permitCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
			permitCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS
			permitCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
			permitCondition[0].ConditionValue.Type = winsys.FWP_V6_ADDR_MASK
			permitCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(permit.prefix))
			permitFilter := winsys.FWPM_FILTER0{}
			permitFilter.FilterCondition = &permitCondition[0]
			permitFilter.NumFilterConditions = 1
			permitFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv6 "+permit.name)
			permitFilter.SubLayerKey = subLayerKey
			permitFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
			permitFilter.Action.Type = winsys.FWP_ACTION_PERMIT
			permitFilter.Weight.Type = winsys.FWP_UINT8
			permitFilter.Weight.Value = uintptr(13)
			err = engine.addFilter(&permitFilter)
			if err != nil {
				return err
			}
		}

		if t.options.DNSModeOrDefault() == DNSModeHijack {
			// The permits above weigh more than the port 53 block, so a query to
			// a local resolver needs its own block between them and the core's
			// permit.
			for _, permit := range permitPrefixes {
				blockDNSCondition := make([]winsys.FWPM_FILTER_CONDITION0, 2)
				blockDNSCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS
				blockDNSCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
				blockDNSCondition[0].ConditionValue.Type = winsys.FWP_V6_ADDR_MASK
				blockDNSCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(permit.prefix))
				blockDNSCondition[1].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_PORT
				blockDNSCondition[1].MatchType = winsys.FWP_MATCH_EQUAL
				blockDNSCondition[1].ConditionValue.Type = winsys.FWP_UINT16
				blockDNSCondition[1].ConditionValue.Value = uintptr(uint16(53))
				blockDNSFilter := winsys.FWPM_FILTER0{}
				blockDNSFilter.FilterCondition = &blockDNSCondition[0]
				blockDNSFilter.NumFilterConditions = 2
				blockDNSFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6 dns "+permit.name)
				blockDNSFilter.SubLayerKey = subLayerKey
				blockDNSFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
				blockDNSFilter.Action.Type = winsys.FWP_ACTION_BLOCK
				blockDNSFilter.Weight.Type = winsys.FWP_UINT8
				blockDNSFilter.Weight.Value = uintptr(14)
				err = engine.addFilter(&blockDNSFilter)
				if err != nil {
					return err
				}
			}
		}

		blockFilter := winsys.FWPM_FILTER0{}
		blockFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6")
		blockFilter.SubLayerKey = subLayerKey
		blockFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		blockFilter.Action.Type = winsys.FWP_ACTION_BLOCK
		blockFilter.Weight.Type = winsys.FWP_UINT8
		blockFilter.Weight.Value = uintptr(12)
		err = engine.addFilter(&blockFilter)
		if err != nil {
			return err
		}
	}

	interfaceIndex, err := lookupInterfaceIndex(t.luid)
	if err != nil {
		return err
	}

	tunCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
	tunCondition[0].FieldKey = winsys.FWPM_CONDITION_LOCAL_INTERFACE_INDEX
	tunCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
	tunCondition[0].ConditionValue.Type = winsys.FWP_UINT32
	tunCondition[0].ConditionValue.Value = uintptr(interfaceIndex)

	if len(t.options.Inet4Address) > 0 {
		tunFilter4 := winsys.FWPM_FILTER0{}
		tunFilter4.FilterCondition = &tunCondition[0]
		tunFilter4.NumFilterConditions = 1
		tunFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv4")
		tunFilter4.SubLayerKey = subLayerKey
		tunFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		tunFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
		tunFilter4.Weight.Type = winsys.FWP_UINT8
		tunFilter4.Weight.Value = uintptr(11)
		err = engine.addFilter(&tunFilter4)
		if err != nil {
			return err
		}
	}

	if len(t.options.Inet6Address) > 0 {
		tunFilter6 := winsys.FWPM_FILTER0{}
		tunFilter6.FilterCondition = &tunCondition[0]
		tunFilter6.NumFilterConditions = 1
		tunFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv6")
		tunFilter6.SubLayerKey = subLayerKey
		tunFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		tunFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
		tunFilter6.Weight.Type = winsys.FWP_UINT8
		tunFilter6.Weight.Value = uintptr(11)
		err = engine.addFilter(&tunFilter6)
		if err != nil {
			return err
		}
	}

	if t.options.DNSModeOrDefault() == DNSModeHijack {
		blockDNSCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
		blockDNSCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_PORT
		blockDNSCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
		blockDNSCondition[0].ConditionValue.Type = winsys.FWP_UINT16
		blockDNSCondition[0].ConditionValue.Value = uintptr(uint16(53))

		blockDNSFilter4 := winsys.FWPM_FILTER0{}
		blockDNSFilter4.FilterCondition = &blockDNSCondition[0]
		blockDNSFilter4.NumFilterConditions = 1
		blockDNSFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv4 dns")
		blockDNSFilter4.SubLayerKey = subLayerKey
		blockDNSFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		blockDNSFilter4.Action.Type = winsys.FWP_ACTION_BLOCK
		blockDNSFilter4.Weight.Type = winsys.FWP_UINT8
		blockDNSFilter4.Weight.Value = uintptr(10)
		err = engine.addFilter(&blockDNSFilter4)
		if err != nil {
			return err
		}

		blockDNSFilter6 := winsys.FWPM_FILTER0{}
		blockDNSFilter6.FilterCondition = &blockDNSCondition[0]
		blockDNSFilter6.NumFilterConditions = 1
		blockDNSFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6 dns")
		blockDNSFilter6.SubLayerKey = subLayerKey
		blockDNSFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		blockDNSFilter6.Action.Type = winsys.FWP_ACTION_BLOCK
		blockDNSFilter6.Weight.Type = winsys.FWP_UINT8
		blockDNSFilter6.Weight.Value = uintptr(10)
		err = engine.addFilter(&blockDNSFilter6)
		if err != nil {
			return err
		}
	}

	return nil
}
