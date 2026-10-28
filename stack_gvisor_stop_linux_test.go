//go:build with_gvisor && linux

package tun

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func countEventFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err == nil && target == "anon_inode:[eventfd]" {
			count++
		}
	}
	return count
}

func newSocketPairGVisor(t *testing.T) (*GVisor, int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	device := &NativeTun{tunFd: pair[0], options: Options{MTU: 1500}}
	return &GVisor{ctx: context.Background(), tun: device}, pair[1]
}

func TestInboundDispatcherEventFDsResolve(t *testing.T) {
	before := countEventFDs(t)
	device := &NativeTun{tunFd: -1, options: Options{MTU: 1500}}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	defer unix.Close(pair[1])
	device.tunFd = pair[0]
	endpoint, _, err := device.NewEndpoint()
	require.NoError(t, err)
	defer func() { require.NoError(t, stopInboundDispatchers(endpoint)) }()

	eventFDs, err := inboundDispatcherEventFDs(&LinkEndpointFilter{LinkEndpoint: endpoint})
	require.NoError(t, err, "the gVisor field path moved")
	require.Len(t, eventFDs, 1)
	_, err = unix.FcntlInt(uintptr(eventFDs[0]), unix.F_GETFD, 0)
	require.NoError(t, err)
	require.Equal(t, before+1, countEventFDs(t))
}

func TestGVisorCloseDoesNotLeakEventFDs(t *testing.T) {
	const rounds = 20
	before := countEventFDs(t)
	for i := 0; i < rounds; i++ {
		gVisor, peer := newSocketPairGVisor(t)
		require.NoError(t, gVisor.Start())
		require.NoError(t, gVisor.Close())
		require.NoError(t, gVisor.Close())
		_ = unix.Close(peer)
		_ = unix.Close(gVisor.tun.(*NativeTun).tunFd)
	}
	require.Equal(t, before, countEventFDs(t), "eventfds leaked over %d start/close cycles", rounds)
}

type badEndpoint struct{ stack.LinkEndpoint }

type endpointWithDispatchers struct {
	stack.LinkEndpoint
	inboundDispatchers []any
}

type dispatcherWithoutStopFD struct{ fd int }

func TestInboundDispatcherEventFDsReturnsErrorOnBadShape(t *testing.T) {
	cases := map[string]stack.LinkEndpoint{
		"no StopFD":         &endpointWithDispatchers{inboundDispatchers: []any{&dispatcherWithoutStopFD{}}},
		"dispatcher is int": &endpointWithDispatchers{inboundDispatchers: []any{1}},
		"nil dispatcher":    &endpointWithDispatchers{inboundDispatchers: []any{(*dispatcherWithoutStopFD)(nil)}},
		"nil interface":     &endpointWithDispatchers{inboundDispatchers: []any{nil}},
		"no slice":          &badEndpoint{},
		"not a pointer":     badEndpoint{},
		"nil pointer":       (*badEndpoint)(nil),
		"filter over bad":   &LinkEndpointFilter{LinkEndpoint: &badEndpoint{}},
	}
	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := inboundDispatcherEventFDs(endpoint)
				require.Error(t, err)
			})
		})
	}
}

func TestGVisorConcurrentCloseClosesDescriptorsOnce(t *testing.T) {
	before := countEventFDs(t)
	gVisor, peer := newSocketPairGVisor(t)
	require.NoError(t, gVisor.Start())
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			require.NoError(t, gVisor.Close())
		}()
	}
	group.Wait()
	require.Equal(t, before, countEventFDs(t))
	_ = unix.Close(peer)
	_ = unix.Close(gVisor.tun.(*NativeTun).tunFd)
}
