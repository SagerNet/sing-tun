package tun

import (
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	goTransmitBackoffMin    = 250 * time.Microsecond
	goTransmitBackoffMax    = time.Millisecond
	goTransmitBackoffBudget = 3 * time.Millisecond
	goDropReportInterval    = time.Second
)

var errGoFrameDropped = E.New("go: frame dropped")

func goIgnoreDropped(err error) error {
	if err == errGoFrameDropped {
		return nil
	}
	return err
}

type goDropCounter struct {
	total      atomic.Uint64
	reported   atomic.Uint64
	reportedAt atomic.Int64
}

func (c *goDropCounter) record(stackLogger logger.Logger, kind string) {
	total := c.total.Add(1)
	now := time.Now().UnixNano()
	previous := c.reportedAt.Load()
	if now-previous < int64(goDropReportInterval) {
		return
	}
	if !c.reportedAt.CompareAndSwap(previous, now) {
		return
	}
	stackLogger.Warn("go: dropped ", total-c.reported.Swap(total), " ", kind, ", ", total, " since start")
}
