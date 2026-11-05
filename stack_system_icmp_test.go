package tun

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/stretchr/testify/require"
)

func TestSystemICMPEcho(t *testing.T) {
	tunAddress4, tunAddress6 := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("fd00::1")
	remote4, remote6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")
	process := func(s *System, source, destination netip.Addr) bool {
		packet := transportPacket(source, destination, 1, []byte{8, 0, 0, 0, 0, 1, 0, 1})
		if source.Is6() {
			packet = transportPacket(source, destination, 58, []byte{128, 0, 0, 0, 0, 1, 0, 1})
			writeBack, err := s.processIPv6ICMP(header.IPv6(packet), header.IPv6(packet).Payload())
			require.NoError(t, err)
			return writeBack
		}
		writeBack, err := s.processIPv4ICMP(header.IPv4(packet), header.IPv4(packet).Payload())
		require.NoError(t, err)
		return writeBack
	}
	for _, mode := range []string{"declined", "error", "tun address"} {
		t.Run(mode, func(t *testing.T) {
			handler := &testHandler{prepare: func(DirectRouteContext) (DirectRouteDestination, error) {
				switch mode {
				case "declined":
					return nil, nil
				case "error":
					return nil, errors.New("dial failed")
				}
				t.Error("echo to the TUN address reached the handler")
				return nil, nil
			}}
			s := &System{
				handler:      handler,
				inet4Address: tunAddress4,
				inet6Address: tunAddress6,
				directNat:    NewDirectRouteMapping(time.Second),
			}
			if mode == "tun address" {
				require.True(t, process(s, netip.MustParseAddr("198.18.0.2"), tunAddress4))
				require.True(t, process(s, netip.MustParseAddr("fd00::2"), tunAddress6))
				return
			}
			require.False(t, process(s, netip.MustParseAddr("198.18.0.2"), remote4), "declined IPv4 echo was answered")
			require.False(t, process(s, netip.MustParseAddr("fd00::2"), remote6), "declined IPv6 echo was answered")
		})
	}
}
