//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const WithGVisor = true

const DefaultNIC tcpip.NICID = 1

// The send buffer is fixed at 256 KiB. A smaller one caps a download over one
// flow at half the speed of a TUN with the room, since the app's ACKs ride a
// round trip through the TUN. The receive buffer is not raised: a larger one
// cost upload speed on a real TUN, and the send buffer alone gives the
// download gain at about 1.3 MiB per slowly read flow.
const (
	gvisorTCPSendBufferSize    = 256 * 1024
	gvisorTCPReceiveBufferSize = 20 * 1024
)

type GVisor struct {
	lifecycle            sync.Mutex
	ctx                  context.Context
	tun                  GVisorTun
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	broadcastAddr        netip.Addr
	handler              Handler
	logger               logger.Logger
	stack                *stack.Stack
	endpoint             stack.LinkEndpoint
}

type GVisorTun interface {
	Tun
	WritePacket(pkt *stack.PacketBuffer) (int, error)
	NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error)
}

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	gTun, isGTun := options.Tun.(GVisorTun)
	if !isGTun {
		return nil, E.New("gVisor stack is unsupported on current platform")
	}

	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	if len(options.TunOptions.Inet4Address) > 0 {
		inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}

	gStack := &GVisor{
		ctx:                  options.Context,
		tun:                  gTun,
		inet4Address:         inet4Address,
		inet6Address:         inet6Address,
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		handler:              options.Handler,
		logger:               options.Logger,
	}
	return gStack, nil
}

func (t *GVisor) Start() error {
	t.lifecycle.Lock()
	defer t.lifecycle.Unlock()
	linkEndpoint, nicOptions, err := t.tun.NewEndpoint()
	if err != nil {
		return err
	}
	linkEndpoint = &LinkEndpointFilter{linkEndpoint, t.broadcastAddr, t.tun}
	// The handlers go in before the NIC exists: creating it attaches the
	// endpoint, whose dispatchers start delivering packets already waiting on
	// the descriptor, and the stack reads the handlers without a lock.
	ipStack := newGVisorStack()
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarderWithLoopback(t.ctx, ipStack, t.handler, t.inet4LoopbackAddress, t.inet6LoopbackAddress, t.tun).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(t.ctx, ipStack, t.handler).HandlePacket)
	icmpForwarder := NewICMPForwarder(t.ctx, ipStack, t.inet4Address, t.inet6Address, t.handler, t.icmpTimeout)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	err = createGVisorNIC(ipStack, linkEndpoint, nicOptions)
	if err != nil {
		t.stopDispatchers(linkEndpoint)
		return err
	}
	t.stack = ipStack
	t.endpoint = linkEndpoint
	return nil
}

func (t *GVisor) Close() error {
	t.lifecycle.Lock()
	defer t.lifecycle.Unlock()
	if t.stack == nil {
		return nil
	}
	endpoint := t.endpoint
	ipStack := t.stack
	t.stack = nil
	t.endpoint = nil
	t.stopDispatchers(endpoint)
	ipStack.Close()
	for _, endpoint := range ipStack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return nil
}

func (t *GVisor) stopDispatchers(endpoint stack.LinkEndpoint) {
	err := stopInboundDispatchers(endpoint)
	if err != nil && t.logger != nil {
		t.logger.Warn("gVisor: eventfd of the inbound dispatchers is left open: ", err)
	}
}

func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}

func NewGVisorStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	return NewGVisorStackWithOptions(ep, stack.NICOptions{})
}

func NewGVisorStackWithOptions(ep stack.LinkEndpoint, opts stack.NICOptions) (*stack.Stack, error) {
	ipStack := newGVisorStack()
	err := createGVisorNIC(ipStack, ep, opts)
	if err != nil {
		return nil, err
	}
	return ipStack, nil
}

func newGVisorStack() *stack.Stack {
	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: gvisorTCPReceiveBufferSize,
		Max:     gvisorTCPReceiveBufferSize,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     gvisorTCPSendBufferSize,
		Default: gvisorTCPSendBufferSize,
		Max:     gvisorTCPSendBufferSize,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	return ipStack
}

// createGVisorNIC attaches the endpoint, which starts its inbound delivery.
func createGVisorNIC(ipStack *stack.Stack, ep stack.LinkEndpoint, opts stack.NICOptions) error {
	err := ipStack.CreateNICWithOptions(DefaultNIC, ep, opts)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: DefaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: DefaultNIC},
	})
	ipStack.SetSpoofing(DefaultNIC, true)
	ipStack.SetPromiscuousMode(DefaultNIC, true)
	return nil
}
