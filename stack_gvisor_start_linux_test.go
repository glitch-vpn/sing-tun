//go:build with_gvisor && linux

package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type packetSignalHandler struct {
	Handler
	packets chan struct{}
}

func (h *packetSignalHandler) NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn N.PacketConn) N.PacketWriter) {
	buffer.Release()
	select {
	case h.packets <- struct{}{}:
	default:
	}
}

func ipv4UDPPacket(source, destination netip.Addr) []byte {
	const payloadLength = 4
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+payloadLength)
	ipHeader := header.IPv4(packet)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     AddressFromAddr(source),
		DstAddr:     AddressFromAddr(destination),
	})
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	udpHeader := header.UDP(ipHeader.Payload())
	udpHeader.Encode(&header.UDPFields{SrcPort: 40000, DstPort: 53, Length: header.UDPMinimumSize + payloadLength})
	return packet
}

// Packets already waiting on the descriptor when the stack starts are
// delivered while Start is still running; run under -race, the transport
// handlers must be installed before the first of them is read.
func TestGVisorStartDeliversPacketsWaitingOnTheDescriptor(t *testing.T) {
	gVisor, peer := newSocketPairGVisor(t)
	handler := &packetSignalHandler{packets: make(chan struct{}, 1)}
	gVisor.handler = handler
	t.Cleanup(func() {
		_ = unix.Close(peer)
		_ = unix.Close(gVisor.tun.(*NativeTun).tunFd)
	})
	packet := ipv4UDPPacket(netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("198.51.100.7"))
	for i := 0; i < 32; i++ {
		_, err := unix.Write(peer, packet)
		require.NoError(t, err)
	}
	require.NoError(t, gVisor.Start())
	t.Cleanup(func() { require.NoError(t, gVisor.Close()) })
	select {
	case <-handler.packets:
	case <-time.After(5 * time.Second):
		t.Fatal("a packet waiting before Start was not delivered")
	}
}
