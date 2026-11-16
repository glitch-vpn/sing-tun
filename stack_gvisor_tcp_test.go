//go:build with_gvisor

package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/stretchr/testify/require"
)

func gvisorSYN(source, destination netip.Addr) *stack.PacketBuffer {
	const tcpLength = header.TCPMinimumSize
	packet := make([]byte, header.IPv6MinimumSize+tcpLength)
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     tcpLength,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           AddressFromAddr(source),
		DstAddr:           AddressFromAddr(destination),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    40000,
		DstPort:    443,
		SeqNum:     1000,
		DataOffset: tcpLength,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(
		header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), tcpLength)))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
}

func gvisorSYNAnswer(t *testing.T, admit TCPAdmission) header.TCPFlags {
	t.Helper()
	SetTCPAdmission(admit)
	t.Cleanup(func() { SetTCPAdmission(nil) })

	link := channel.New(8, 1500, "")
	ipStack, err := NewGVisorStack(link)
	require.NoError(t, err)
	t.Cleanup(func() { ipStack.Close() })
	forwarder := NewTCPForwarder(t.Context(), ipStack, &testHandler{})
	ipStack.SetTransportProtocolHandler(header.TCPProtocolNumber, forwarder.HandlePacket)

	link.InjectInbound(header.IPv6ProtocolNumber, gvisorSYN(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2607:f8b0::1")))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reply := link.Read(); reply != nil {
			defer reply.DecRef()
			return header.TCP(reply.ToView().AsSlice()[header.IPv6MinimumSize:]).Flags()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the stack never answered the SYN")
	return 0
}

func TestGVisorTCPAdmissionRefusedSYNIsReset(t *testing.T) {
	var asked netip.AddrPort
	flags := gvisorSYNAnswer(t, func(destination netip.AddrPort) bool {
		asked = destination
		return false
	})
	require.NotZero(t, flags&header.TCPFlagRst, "no reset for a refused SYN")
	require.Zero(t, flags&header.TCPFlagSyn, "a refused SYN was answered with a SYN-ACK")
	require.Equal(t, netip.MustParseAddrPort("[2607:f8b0::1]:443"), asked)
}

func TestGVisorTCPAdmissionAdmittedSYNIsAnswered(t *testing.T) {
	flags := gvisorSYNAnswer(t, func(netip.AddrPort) bool { return true })
	require.NotZero(t, flags&header.TCPFlagSyn)
	require.NotZero(t, flags&header.TCPFlagAck)
}

func TestGVisorWithoutTCPAdmissionAnswersEverySYN(t *testing.T) {
	flags := gvisorSYNAnswer(t, nil)
	require.NotZero(t, flags&header.TCPFlagSyn)
}
