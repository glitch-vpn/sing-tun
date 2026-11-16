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

func gvisorSYNAnswer(t *testing.T, admit TCPAdmission, wait time.Duration) (header.TCPFlags, bool) {
	t.Helper()
	SetTCPAdmission(admit)
	t.Cleanup(func() { SetTCPAdmission(nil) })

	link := channel.New(8, 1500, "")
	ipStack, err := NewGVisorStack(link)
	require.NoError(t, err)
	t.Cleanup(func() { ipStack.Close() })
	forwarder := NewTCPForwarder(t.Context(), ipStack, &testHandler{})
	ipStack.SetTransportProtocolHandler(header.TCPProtocolNumber, forwarder.HandlePacket)

	syn := func() {
		link.InjectInbound(header.IPv6ProtocolNumber, gvisorSYN(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2607:f8b0::1")))
	}
	syn()
	flags, answered := readSYNAnswer(link, wait)
	if !answered && wait < time.Second {
		// A dropped SYN is judged again when the client retransmits it.
		syn()
		flags, answered = readSYNAnswer(link, time.Second)
	}
	return flags, answered
}

func readSYNAnswer(link *channel.Endpoint, wait time.Duration) (header.TCPFlags, bool) {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if reply := link.Read(); reply != nil {
			defer reply.DecRef()
			return header.TCP(reply.ToView().AsSlice()[header.IPv6MinimumSize:]).Flags(), true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, false
}

func TestGVisorTCPAdmissionRefusedSYNIsReset(t *testing.T) {
	var asked netip.AddrPort
	flags, answered := gvisorSYNAnswer(t, func(destination netip.AddrPort) TCPVerdict {
		asked = destination
		return TCPReset
	}, time.Second)
	require.True(t, answered)
	require.NotZero(t, flags&header.TCPFlagRst, "no reset for a refused SYN")
	require.Zero(t, flags&header.TCPFlagSyn, "a refused SYN was answered with a SYN-ACK")
	require.Equal(t, netip.MustParseAddrPort("[2607:f8b0::1]:443"), asked)
}

func TestGVisorTCPAdmissionDroppedSYNIsJudgedAgainOnRetransmit(t *testing.T) {
	verdicts := []TCPVerdict{TCPDrop, TCPAdmit}
	asked := 0
	flags, answered := gvisorSYNAnswer(t, func(netip.AddrPort) TCPVerdict {
		v := verdicts[asked]
		asked++
		return v
	}, 300*time.Millisecond)
	require.True(t, answered, "the retransmitted SYN was not answered")
	require.Equal(t, 2, asked)
	require.NotZero(t, flags&header.TCPFlagSyn)
}

func TestGVisorTCPAdmissionAdmittedSYNIsAnswered(t *testing.T) {
	flags, answered := gvisorSYNAnswer(t, func(netip.AddrPort) TCPVerdict { return TCPAdmit }, time.Second)
	require.True(t, answered)
	require.NotZero(t, flags&header.TCPFlagSyn)
	require.NotZero(t, flags&header.TCPFlagAck)
}

func TestGVisorWithoutTCPAdmissionAnswersEverySYN(t *testing.T) {
	flags, answered := gvisorSYNAnswer(t, nil, time.Second)
	require.True(t, answered)
	require.NotZero(t, flags&header.TCPFlagSyn)
}
