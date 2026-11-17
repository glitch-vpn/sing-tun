//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/stretchr/testify/require"
)

// A TCP connection's send buffer is a fixed 256 KiB and its receive buffer
// keeps its 20 KiB window, which receive buffer moderation may grow.
func TestGVisorStackTCPBuffers(t *testing.T) {
	s, err := NewGVisorStack(channel.New(8, 1500, ""))
	require.NoError(t, err)
	t.Cleanup(s.Close)

	var receive tcpip.TCPReceiveBufferSizeRangeOption
	require.Nil(t, s.TransportProtocolOption(header.TCPProtocolNumber, &receive))
	require.Equal(t, tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: 20 * 1024, Max: 20 * 1024}, receive)

	var send tcpip.TCPSendBufferSizeRangeOption
	require.Nil(t, s.TransportProtocolOption(header.TCPProtocolNumber, &send))
	require.Equal(t, tcpip.TCPSendBufferSizeRangeOption{Min: 256 * 1024, Default: 256 * 1024, Max: 256 * 1024}, send)

	var moderate tcpip.TCPModerateReceiveBufferOption
	require.Nil(t, s.TransportProtocolOption(header.TCPProtocolNumber, &moderate))
	require.True(t, bool(moderate))
}
