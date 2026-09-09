//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

type recordingEndpoint struct {
	stack.LinkEndpoint
	attached stack.NetworkDispatcher
	calls    int
}

func (e *recordingEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.attached = dispatcher
	e.calls++
}

type noopDispatcher struct {
	stack.NetworkDispatcher
}

// Close detaches by attaching a nil dispatcher, and the fdbased endpoint only
// stops its inbound dispatchers when it receives a literal nil.
func TestLinkEndpointFilterAttachNil(t *testing.T) {
	endpoint := &recordingEndpoint{}
	filter := &LinkEndpointFilter{LinkEndpoint: endpoint}

	filter.Attach(nil)

	if endpoint.calls != 1 {
		t.Fatalf("expected one Attach on the wrapped endpoint, got %d", endpoint.calls)
	}
	if endpoint.attached != nil {
		t.Fatalf("expected the detach to reach the endpoint as nil, got %#v", endpoint.attached)
	}
}

func TestLinkEndpointFilterAttachDispatcher(t *testing.T) {
	endpoint := &recordingEndpoint{}
	filter := &LinkEndpointFilter{LinkEndpoint: endpoint}

	filter.Attach(&noopDispatcher{})

	if endpoint.calls != 1 {
		t.Fatalf("expected one Attach on the wrapped endpoint, got %d", endpoint.calls)
	}
	if _, ok := endpoint.attached.(*networkDispatcherFilter); !ok {
		t.Fatalf("expected the dispatcher to stay wrapped, got %T", endpoint.attached)
	}
}
