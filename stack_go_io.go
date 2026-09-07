package tun

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	goTransmitBackoffMin    = 250 * time.Microsecond
	goTransmitBackoffMax    = time.Millisecond
	goTransmitBackoffBudget = 3 * time.Millisecond
	goDropReportInterval    = time.Second
)

var errGoFrameDropped = E.New("go: frame dropped")

type goFrame struct {
	buffer *buf.Buffer
	meta   ForwardFrameMeta
}

type goSocketEvent struct {
	token    uint32
	readable bool
	writable bool
}

const (
	goInterestRead uint8 = 1 << iota
	goInterestWrite
)

var errGoQueueUnavailable = E.New("go: tun queue unavailable")

type goPlatformIO interface {
	start() error
	wait(timeout time.Duration, events []goSocketEvent) (tunReadable bool, count int, err error)
	registerSocket(socket *goSocket, token uint32, interest uint8) error
	updateSocket(socket *goSocket, interest uint8) error
	unregisterSocket(socket *goSocket)
	readBurst(frames []goFrame, options N.ReadWaitOptions) (count int, drained bool, err error)
	writeFrame(frame [][]byte, meta ForwardFrameMeta) error
	writeData(frame [][]byte, meta ForwardFrameMeta) error
	writePacketBatch(frames []goUDPFrame) error
	releaseReadBuffers()
	flush()
	transmitPrefix() int
	transmitChecksumOffload() bool
	transmitSegmentOffload() bool
	armTransmitWritable() (bool, error)
	takeTransmitWritable() bool
	wake()
	close() error
}

type goWriteback struct {
	platformIO goPlatformIO
}

func (w *goWriteback) ReturnHeadroom() int {
	return w.platformIO.transmitPrefix()
}

func (w *goWriteback) WriteReturnPackets(packets [][]byte) error {
	prefix := w.platformIO.transmitPrefix()
	var writeErr error
	for _, packet := range packets {
		writeErr = E.Errors(writeErr, goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet[prefix:]}, ForwardFrameMeta{})))
	}
	return writeErr
}

func newGoReadBuffers(packetSize int, count int, options N.ReadWaitOptions) []*buf.Buffer {
	slotSize := options.FrontHeadroom + packetSize + options.RearHeadroom
	buffers := make([]*buf.Buffer, count)
	for index := range buffers {
		buffer := buf.NewSize(slotSize)
		buffer.Resize(options.FrontHeadroom, 0)
		buffer.Reserve(options.RearHeadroom)
		buffers[index] = buffer
	}
	return buffers
}

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
