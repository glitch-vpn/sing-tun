//go:build with_gvisor && linux

package tun

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	"golang.org/x/sys/unix"
)

// stopInboundDispatchers detaches the endpoint, waits for its inbound
// dispatchers to return and closes the eventfd each of them was stopped through.
//
// gVisor's fdbased endpoint creates that eventfd, the stopfd.StopFD embedded in
// every inbound dispatcher, and never closes it: Attach(nil) writes to it and
// the dispatch goroutine returns, but the descriptor stays open, one per stack
// start. The dispatchers are unexported, so the descriptors are read through
// reflect, read-only, and a shape that is not the expected one is an error and
// leaves them open.
//
// The descriptors are closed only after Attach(nil) and Wait have returned,
// when no goroutine polls or writes them. It must be called once per endpoint:
// a second call would close the descriptors twice. The endpoint is not
// attachable afterwards.
func stopInboundDispatchers(endpoint stack.LinkEndpoint) error {
	endpoint.Attach(nil)
	endpoint.Wait()

	eventFDs, err := inboundDispatcherEventFDs(endpoint)
	if err != nil {
		return err
	}
	var closeErr error
	for _, eventFD := range eventFDs {
		if err := unix.Close(eventFD); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}

// inboundDispatcherEventFDs returns the stop eventfd of every inbound
// dispatcher of an fdbased endpoint, looking through LinkEndpointFilter.
func inboundDispatcherEventFDs(endpoint stack.LinkEndpoint) ([]int, error) {
	for {
		filter, isFilter := endpoint.(*LinkEndpointFilter)
		if !isFilter {
			break
		}
		endpoint = filter.LinkEndpoint
	}
	value := reflect.ValueOf(endpoint)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("endpoint is %T, not a pointer to a struct", endpoint)
	}
	dispatchers := value.Elem().FieldByName("inboundDispatchers")
	if !dispatchers.IsValid() || dispatchers.Kind() != reflect.Slice {
		return nil, fmt.Errorf("endpoint %T has no inboundDispatchers slice", endpoint)
	}
	eventFDs := make([]int, 0, dispatchers.Len())
	for i := 0; i < dispatchers.Len(); i++ {
		dispatcher := dispatchers.Index(i)
		if dispatcher.Kind() == reflect.Interface {
			if dispatcher.IsNil() {
				return nil, fmt.Errorf("inbound dispatcher %d is nil", i)
			}
			dispatcher = dispatcher.Elem()
		}
		if dispatcher.Kind() != reflect.Pointer || dispatcher.IsNil() || dispatcher.Elem().Kind() != reflect.Struct {
			return nil, fmt.Errorf("inbound dispatcher %d is not a pointer to a struct", i)
		}
		stopFD := dispatcher.Elem().FieldByName("StopFD")
		if !stopFD.IsValid() || stopFD.Kind() != reflect.Struct {
			return nil, fmt.Errorf("inbound dispatcher %d (%s) has no StopFD", i, dispatcher.Type())
		}
		eventFD := stopFD.FieldByName("EFD")
		if !eventFD.IsValid() || eventFD.Kind() != reflect.Int {
			return nil, fmt.Errorf("inbound dispatcher %d (%s) has no StopFD.EFD", i, dispatcher.Type())
		}
		eventFDs = append(eventFDs, int(eventFD.Int()))
	}
	return eventFDs, nil
}
