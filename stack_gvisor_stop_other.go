//go:build with_gvisor && !linux

package tun

import "github.com/metacubex/gvisor/pkg/tcpip/stack"

func stopInboundDispatchers(endpoint stack.LinkEndpoint) error {
	endpoint.Attach(nil)
	return nil
}
