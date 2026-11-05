//go:build with_gvisor

package tun

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing/common/buf"
	"github.com/stretchr/testify/require"
)

type recordingDestination struct {
	packets chan []byte
}

func (d *recordingDestination) IsClosed() bool { return false }
func (d *recordingDestination) Close() error   { return nil }
func (d *recordingDestination) WritePacket(b *buf.Buffer) error {
	defer b.Release()
	d.packets <- append([]byte(nil), b.Bytes()...)
	return nil
}

func gvisorEchoRequest(source, destination netip.Addr) *stack.PacketBuffer {
	payload := []byte{1, 2, 3, 4}
	if source.Is4() {
		packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
		ipHdr := header.IPv4(packet)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(packet)),
			TTL:         64,
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			SrcAddr:     AddressFromAddr(source),
			DstAddr:     AddressFromAddr(destination),
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		icmpHdr.SetType(header.ICMPv4Echo)
		copy(icmpHdr.Payload(), payload)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
		return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	}
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize+len(payload))
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6MinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           AddressFromAddr(source),
		DstAddr:           AddressFromAddr(destination),
	})
	icmpHdr := header.ICMPv6(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
}

func TestGVisorICMPEcho(t *testing.T) {
	tunAddress4, tunAddress6 := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("fd00::1")
	for _, family := range []struct {
		name        string
		protocol    tcpip.NetworkProtocolNumber
		source      netip.Addr
		local       netip.Addr
		remote      netip.Addr
		replyOffset int
		replyType   byte
	}{
		{"ipv4", header.IPv4ProtocolNumber, netip.MustParseAddr("198.18.0.2"), tunAddress4, netip.MustParseAddr("8.8.8.8"), header.IPv4MinimumSize, byte(header.ICMPv4EchoReply)},
		{"ipv6", header.IPv6ProtocolNumber, netip.MustParseAddr("fd00::2"), tunAddress6, netip.MustParseAddr("2001:4860:4860::8888"), header.IPv6MinimumSize, byte(header.ICMPv6EchoReply)},
	} {
		for _, mode := range []string{"declined", "error", "forwarded", "tun address"} {
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				link := channel.New(8, 1500, "")
				ipStack, err := NewGVisorStack(link)
				require.NoError(t, err)
				t.Cleanup(func() { ipStack.Close() })
				forwarded := &recordingDestination{packets: make(chan []byte, 1)}
				handler := &testHandler{prepare: func(DirectRouteContext) (DirectRouteDestination, error) {
					switch mode {
					case "declined":
						return nil, nil
					case "error":
						return nil, errors.New("dial failed")
					case "tun address":
						t.Error("echo to the TUN address reached the handler")
					}
					return forwarded, nil
				}}
				forwarder := NewICMPForwarder(t.Context(), ipStack, tunAddress4, tunAddress6, handler, time.Second)
				protocol := header.ICMPv4ProtocolNumber
				if family.source.Is6() {
					protocol = header.ICMPv6ProtocolNumber
				}
				ipStack.SetTransportProtocolHandler(protocol, forwarder.HandlePacket)

				target := family.remote
				if mode == "tun address" {
					target = family.local
				}
				link.InjectInbound(family.protocol, gvisorEchoRequest(family.source, target))

				select {
				case packet := <-forwarded.packets:
					require.Equal(t, "forwarded", mode)
					require.NotEmpty(t, packet)
					return
				case <-time.After(200 * time.Millisecond):
				}
				reply := link.Read()
				switch mode {
				case "declined", "error":
					require.Nil(t, reply, "a declined echo was answered")
				case "forwarded":
					t.Fatal("echo was not forwarded")
				case "tun address":
					require.NotNil(t, reply, "echo to the TUN address was not answered")
					defer reply.DecRef()
					raw := reply.ToView().AsSlice()
					require.Equal(t, family.replyType, raw[family.replyOffset])
				}
			})
		}
	}
}
