package ping

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestSourceRewriterTimeoutCleanup(t *testing.T) {
	t.Parallel()

	rewriter := NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		netip.MustParseAddr("10.0.0.1"),
		netip.Addr{},
	)

	addr := netip.MustParseAddr("192.168.1.1")
	dest := netip.MustParseAddr("1.1.1.1")

	// Insert an entry
	key := sourceKey{Protocol: 1, Port: 100, Destination: dest}
	rewriter.access.Lock()
	rewriter.sourceAddress[key] = addr
	rewriter.access.Unlock()

	// The entry should be found
	rewriter.access.RLock()
	found, ok := rewriter.sourceAddress[key]
	rewriter.access.RUnlock()
	require.True(t, ok, "entry should be found")
	require.Equal(t, addr, found)

	// Delete and verify gone
	rewriter.access.Lock()
	delete(rewriter.sourceAddress, key)
	rewriter.access.Unlock()

	rewriter.access.RLock()
	_, ok = rewriter.sourceAddress[key]
	rewriter.access.RUnlock()
	require.False(t, ok, "deleted entry should not be found")
}

func TestSourceRewriterCapacityLimit(t *testing.T) {
	t.Parallel()

	rewriter := NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		netip.MustParseAddr("10.0.0.1"),
		netip.Addr{},
	)

	addr := netip.MustParseAddr("192.168.1.1")
	dest := netip.MustParseAddr("1.1.1.1")

	// Insert multiple entries with different keys
	for i := uint16(0); i < 100; i++ {
		rewriter.access.Lock()
		rewriter.sourceAddress[sourceKey{Protocol: 1, Port: i, Destination: dest}] = addr
		rewriter.access.Unlock()
	}
	require.Equal(t, 100, len(rewriter.sourceAddress))

	// The newest entry should exist
	rewriter.access.RLock()
	_, ok := rewriter.sourceAddress[sourceKey{Protocol: 1, Port: 99, Destination: dest}]
	rewriter.access.RUnlock()
	require.True(t, ok, "entry should exist")
}
