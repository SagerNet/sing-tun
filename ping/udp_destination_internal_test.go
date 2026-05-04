package ping

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/stretchr/testify/require"
)

func TestRegisterRequest(t *testing.T) {
	t.Parallel()
	requests := common.Must1(freelru.NewSynced[uint16, struct{}](udpRequestsCapacity, maphash.NewHasher[uint16]().Hash32))
	requests.SetLifetime(5 * time.Second)
	d := &UDPDestination{
		timeout:  5 * time.Second,
		requests: requests,
	}

	d.requests.Add(33434, struct{}{})
	d.requests.Add(33435, struct{}{})
	d.requests.Add(33436, struct{}{})

	require.Equal(t, 3, d.requests.Len())
	require.True(t, d.requests.Contains(33434))
	require.True(t, d.requests.Contains(33435))
	require.True(t, d.requests.Contains(33436))
}

func TestRegisterRequestExpiry(t *testing.T) {
	t.Parallel()
	requests := common.Must1(freelru.NewSynced[uint16, struct{}](udpRequestsCapacity, maphash.NewHasher[uint16]().Hash32))
	requests.SetLifetime(50 * time.Millisecond)
	d := &UDPDestination{
		timeout:  50 * time.Millisecond,
		requests: requests,
	}

	d.requests.Add(33434, struct{}{})
	time.Sleep(100 * time.Millisecond)

	require.False(t, d.requests.Contains(33434), "expired request should not be found")

	d.requests.Add(33435, struct{}{})
	require.True(t, d.requests.Contains(33435), "new request should exist")
}

func TestRegisterRequestLimit(t *testing.T) {
	t.Parallel()
	requests := common.Must1(freelru.NewSynced[uint16, struct{}](udpRequestsCapacity, maphash.NewHasher[uint16]().Hash32))
	requests.SetLifetime(1 * time.Hour)
	d := &UDPDestination{
		timeout:  1 * time.Hour,
		requests: requests,
	}

	// Fill beyond capacity — LRU eviction keeps size bounded
	for i := uint16(0); i < udpRequestsCapacity+100; i++ {
		d.requests.Add(i, struct{}{})
	}

	require.LessOrEqual(t, d.requests.Len(), udpRequestsCapacity,
		"request count should not exceed capacity")
}

func TestOriginalSourcePort(t *testing.T) {
	t.Parallel()
	requests := common.Must1(freelru.NewSynced[uint16, struct{}](udpRequestsCapacity, maphash.NewHasher[uint16]().Hash32))
	d := &UDPDestination{
		timeout:   5 * time.Second,
		requests:  requests,
		localPort: 23674,
	}

	d.originalSource.Store(netip.MustParseAddr("10.0.0.2"))
	d.originalSourcePort = 60183

	require.Equal(t, uint16(23674), d.localPort)
	require.Equal(t, uint16(60183), d.originalSourcePort)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), d.originalSource.Load())
}
