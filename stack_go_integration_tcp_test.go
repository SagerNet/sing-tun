//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	N "github.com/sagernet/sing/common/network"
)

const kernelTCPTimeout = 3 * time.Second

type kernelTCPEvent struct {
	at       time.Duration
	rate     uint64
	outgoing bool
	sequence uint64
	end      uint64
	ack      uint64
	window   uint16
	length   int
	sacks    []goSackBlock
	flags    header.TCPFlags
	dropped  bool
	delayed  bool
	delivery bool
	copies   int
}

type kernelTCPAction struct {
	drop   bool
	copies int
	delay  time.Duration
	pause  *kernelTCPBarrier
}

type kernelTCPBarrier struct {
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func newKernelTCPBarrier(t *testing.T) *kernelTCPBarrier {
	barrier := &kernelTCPBarrier{entered: make(chan struct{}), resume: make(chan struct{})}
	t.Cleanup(func() { barrier.once.Do(func() { close(barrier.resume) }) })
	return barrier
}

type kernelTCPConfig struct {
	receiveDelay      time.Duration
	disableSACK       bool
	disableTimestamps bool
	checkpoint        func(string, *GoConn)
}

type kernelTCPFlow struct {
	conn       *GoConn
	isn        uint32
	sent       uint64
	acked      uint64
	fin        uint64
	peerFIN    bool
	peerWindow uint16
	failure    string
	events     []kernelTCPEvent
	processed  uint64
	closed     bool
	released   bool
	writes     int
	faults     uint64
	filter     func(kernelTCPEvent) kernelTCPAction
}

type kernelTCPHarness struct {
	access  sync.Mutex
	flows   map[flowKey]*kernelTCPFlow
	changed chan struct{}
	done    chan struct{}
	epoch   time.Time
	config  kernelTCPConfig
	workers sync.WaitGroup
	stopped bool
}

func newKernelTCPFixture(t *testing.T, config kernelStackConfig, tcpConfig kernelTCPConfig) (*kernelStackFixture, *kernelTCPHarness) {
	t.Helper()
	harness := &kernelTCPHarness{
		flows: make(map[flowKey]*kernelTCPFlow), changed: make(chan struct{}, 1), done: make(chan struct{}),
		epoch: time.Now(), config: tcpConfig,
	}
	prepare := config.prepareStack
	config.prepareStack = func(stack *Go) {
		if prepare != nil {
			prepare(stack)
		}
		queues := stack.queueFactory
		stack.queueFactory = func(current *Go) ([]goPlatformIO, error) {
			platforms, err := queues(current)
			if err != nil {
				return nil, err
			}
			for index, platform := range platforms {
				platforms[index] = &kernelTCPIO{goPlatformIO: platform, harness: harness}
			}
			return platforms, nil
		}
		operations := *stack.congestion
		initialize := operations.init
		operations.init = func(conn *GoConn) {
			if initialize != nil {
				initialize(conn)
			}
			harness.access.Lock()
			harness.flows[conn.key] = &kernelTCPFlow{conn: conn, isn: conn.sendISN}
			harness.access.Unlock()
		}
		release := operations.release
		operations.release = func(conn *GoConn) {
			harness.access.Lock()
			flow := harness.flows[conn.key]
			flow.released = true
			if flow.writes != 0 && flow.failure == "" {
				flow.failure = fmt.Sprintf("connection resources released with %d device writes in progress", flow.writes)
			}
			harness.access.Unlock()
			if release != nil {
				release(conn)
			}
		}
		checkpoint := tcpConfig.checkpoint
		if checkpoint != nil {
			acked := operations.packetsAcked
			operations.packetsAcked = func(conn *GoConn, sample *goAckSample) {
				if sample.packetsAcked > 0 {
					checkpoint("ack", conn)
				}
				if acked != nil {
					acked(conn, sample)
				}
			}
			avoid := operations.congAvoid
			if avoid != nil {
				operations.congAvoid = func(conn *GoConn, packets uint32) {
					checkpoint("control", conn)
					avoid(conn, packets)
					checkpoint("controlled", conn)
				}
			}
			control := operations.congControl
			if control != nil {
				operations.congControl = func(conn *GoConn, flags goAckFlags, sample *goRateSample) {
					checkpoint("control", conn)
					control(conn, flags, sample)
					checkpoint("controlled", conn)
				}
			}
		}
		stack.congestion = &operations
	}
	fixture := newKernelStackFixture(t, config)
	t.Cleanup(func() {
		harness.access.Lock()
		harness.stopped = true
		close(harness.done)
		harness.access.Unlock()
		harness.workers.Wait()
	})
	return fixture, harness
}

func (h *kernelTCPHarness) eventLocked(packet []byte, outgoing bool) (*kernelTCPFlow, kernelTCPEvent) {
	parsed, valid := parseForwardPacket(packet)
	if !valid || parsed.protocol != uint8(header.TCPProtocolNumber) {
		return nil, kernelTCPEvent{}
	}
	key := parsed.flowKey()
	if outgoing {
		key = key.reversed()
	}
	flow := h.flows[key]
	if flow == nil {
		return nil, kernelTCPEvent{}
	}
	tcp := header.TCP(parsed.transport)
	flags := tcp.Flags()
	event := kernelTCPEvent{at: time.Since(h.epoch), outgoing: outgoing, flags: flags, window: tcp.WindowSize(), length: len(tcp.Payload())}
	if outgoing {
		event.rate = flow.conn.pacingRate.Load()
		event.sequence = uint64(uint32(tcp.SequenceNumber() - flow.isn))
		event.end = event.sequence + uint64(len(tcp.Payload()))
		if flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
			event.end++
		}
	} else {
		event.ack = uint64(uint32(tcp.AckNumber() - flow.isn))
		for _, block := range header.ParseTCPOptions(tcp.Options()).SACKBlocks {
			event.sacks = append(event.sacks, goSackBlock{
				start: uint64(uint32(block.Start) - flow.isn),
				end:   uint64(uint32(block.End) - flow.isn),
			})
		}
	}
	return flow, event
}

func (h *kernelTCPHarness) recordLocked(flow *kernelTCPFlow, event kernelTCPEvent) {
	if event.outgoing {
		if !event.delivery && event.end > event.sequence && event.end <= flow.processed && flow.peerWindow != 0 && flow.failure == "" {
			flow.failure = fmt.Sprintf("retransmitted acknowledged sequence [%d,%d), processed ACK %d", event.sequence, event.end, flow.processed)
		}
		flow.sent = max(flow.sent, event.end)
		if event.flags&header.TCPFlagFin != 0 {
			flow.fin = event.end
		}
	} else if !event.dropped && !event.delayed {
		flow.peerWindow = event.window
		if event.flags&header.TCPFlagAck != 0 {
			flow.acked = max(flow.acked, event.ack)
		}
		flow.peerFIN = flow.peerFIN || event.flags&header.TCPFlagFin != 0
	}
	if !event.delivery && (event.dropped || event.delayed || event.copies > 1) {
		flow.faults++
	}
	if len(flow.events) == 128 {
		copy(flow.events, flow.events[1:])
		flow.events = flow.events[:127]
	}
	flow.events = append(flow.events, event)
	select {
	case h.changed <- struct{}{}:
	default:
	}
}

func (h *kernelTCPHarness) pair(t *testing.T, fixture *kernelStackFixture, ipv6 bool, writer string) (*net.TCPConn, net.Conn, *GoConn) {
	t.Helper()
	var client *net.TCPConn
	var sender net.Conn
	if writer == "splice" {
		client, sender, _, _ = fixture.splicePair(t, ipv6)
	} else {
		client, sender = fixture.pair(t, ipv6)
	}
	key := flowKey{protocol: uint8(header.TCPProtocolNumber), source: client.LocalAddr().(*net.TCPAddr).AddrPort(), destination: client.RemoteAddr().(*net.TCPAddr).AddrPort()}
	return client, sender, h.snapshot(key).conn
}

func (h *kernelTCPHarness) setFilter(conn *GoConn, filter func(kernelTCPEvent) kernelTCPAction) {
	h.access.Lock()
	h.flows[conn.key].filter = filter
	h.access.Unlock()
}

func (h *kernelTCPHarness) inspectLocked(platform *kernelTCPIO) {
	for _, flow := range h.flows {
		conn := flow.conn
		if conn.engine.platformIO != platform {
			continue
		}
		flow.processed = conn.sendUnacked.Load()
		flow.closed = conn.closed()
		if flow.closed || flow.failure != "" {
			continue
		}
		flight := conn.flight
		if uint64(flight.sackedOut)+uint64(flight.lostOut) > uint64(flight.packetsOut) ||
			uint64(flight.sackedOut)+uint64(flight.retransmitOut) > uint64(flight.packetsOut) {
			flow.failure = fmt.Sprintf("invalid flight accounting: %+v", flight)
		}
		if conn.sendReleased.Load() > min(flow.processed, conn.transmittedTail.Load()) {
			flow.failure = "send buffers released before transmission and acknowledgement completed"
		}
	}
}

func (h *kernelTCPHarness) snapshot(key flowKey) kernelTCPFlow {
	h.access.Lock()
	defer h.access.Unlock()
	flow := *h.flows[key]
	flow.events = slices.Clone(flow.events)
	return flow
}

func (h *kernelTCPHarness) await(t *testing.T, conn *GoConn, description string, ready func(kernelTCPFlow) bool) kernelTCPFlow {
	t.Helper()
	timer := time.NewTimer(kernelTCPTimeout)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		flow := h.snapshot(conn.key)
		if flow.failure != "" {
			t.Fatalf("%s: %s; recent TCP events: %+v", description, flow.failure, flow.events[max(0, len(flow.events)-16):])
		}
		if ready(flow) {
			return flow
		}
		select {
		case <-h.changed:
		case <-tick.C:
		case <-timer.C:
			t.Fatalf("%s timed out: sent=%d ACK=%d processed=%d FIN=%d peerFIN=%v closed=%v; recent TCP events: %+v", description, flow.sent, flow.acked, flow.processed, flow.fin, flow.peerFIN, conn.closed(), flow.events[max(0, len(flow.events)-16):])
		}
	}
}

type kernelTCPIO struct {
	goPlatformIO
	harness *kernelTCPHarness
}

func (p *kernelTCPIO) close() error {
	p.harness.access.Lock()
	p.harness.inspectLocked(p)
	p.harness.access.Unlock()
	return p.goPlatformIO.close()
}

func (p *kernelTCPIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	p.harness.access.Lock()
	p.harness.inspectLocked(p)
	p.harness.access.Unlock()
	if p.harness.config.checkpoint != nil {
		p.harness.config.checkpoint("idle", nil)
	}
	readable, count, err := p.goPlatformIO.wait(timeout, events)
	if readable && p.harness.config.receiveDelay > 0 {
		timer := time.NewTimer(p.harness.config.receiveDelay)
		select {
		case <-timer.C:
		case <-p.harness.done:
		}
		timer.Stop()
	}
	return readable, count, err
}

func (p *kernelTCPIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	if p.harness.config.checkpoint != nil {
		p.harness.config.checkpoint("receive", nil)
	}
	n, drained, err := p.goPlatformIO.readBurst(frames, options)
	p.harness.access.Lock()
	kept := 0
	for index := range n {
		frame := frames[index]
		packet := frame.buffer.Bytes()
		p.rewriteSynOptions(packet)
		flow, event := p.harness.eventLocked(packet, false)
		if flow != nil {
			action := kernelTCPAction{}
			if flow.filter != nil {
				action = flow.filter(event)
			}
			event.dropped = action.drop
			event.delayed = action.delay > 0
			event.copies = max(action.copies, 1)
			p.harness.recordLocked(flow, event)
			if action.drop {
				continue
			}
			if action.delay > 0 {
				p.delayLocked(flow, event, packet, frame.meta, nil, 0, action.delay)
				continue
			}
			for copyIndex := 1; copyIndex < action.copies; copyIndex++ {
				flow.conn.engine.inject(packet, frame.meta)
			}
		}
		frames[kept] = frame
		kept++
	}
	p.harness.access.Unlock()
	return kept, drained, err
}

func (p *kernelTCPIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	return p.write(frame, meta, nil, 0)
}

func (p *kernelTCPIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	return p.write([][]byte{packet}, meta, nil, 0)
}

func (p *kernelTCPIO) writeData(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	return p.write(frame, meta, owner, segmentEnd)
}

func (p *kernelTCPIO) write(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	packet := slices.Concat(frame...)
	p.harness.access.Lock()
	flow, event := p.harness.eventLocked(packet, true)
	action := kernelTCPAction{}
	if flow != nil {
		flow.writes++
		if flow.filter != nil {
			action = flow.filter(event)
		}
	}
	if action.pause != nil {
		p.harness.access.Unlock()
		close(action.pause.entered)
		select {
		case <-action.pause.resume:
		case <-p.harness.done:
		}
		p.harness.access.Lock()
	}
	var err error
	event.copies = max(action.copies, 1)
	switch {
	case action.drop:
		event.dropped = true
	case action.delay > 0:
		event.delayed = true
		p.delayLocked(flow, event, packet, meta, owner, segmentEnd, action.delay)
	default:
		for range event.copies {
			if owner != nil {
				err = p.goPlatformIO.writeData(frame, meta, owner, segmentEnd)
			} else {
				err = p.goPlatformIO.writeFrame(frame, meta)
			}
			if err != nil {
				break
			}
		}
	}
	if flow != nil {
		if err == nil {
			p.harness.recordLocked(flow, event)
		}
		flow.writes--
	}
	if owner != nil {
		p.goPlatformIO.flush()
	}
	p.harness.access.Unlock()
	return err
}

func (p *kernelTCPIO) delayLocked(flow *kernelTCPFlow, event kernelTCPEvent, packet []byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64, delay time.Duration) {
	if p.harness.stopped {
		return
	}
	packet = slices.Clone(packet)
	p.harness.workers.Go(func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-p.harness.done:
			return
		case <-timer.C:
		}
		p.harness.access.Lock()
		defer p.harness.access.Unlock()
		if p.harness.stopped || flow.conn.closed() {
			return
		}
		event.at = time.Since(p.harness.epoch)
		event.delayed = false
		event.delivery = true
		for range event.copies {
			if event.outgoing {
				err := p.goPlatformIO.writeData([][]byte{packet}, meta, owner, segmentEnd)
				p.goPlatformIO.flush()
				if err != nil && flow.failure == "" {
					flow.failure = fmt.Sprintf("deliver delayed packet: %v", err)
				}
			} else {
				flow.conn.engine.inject(packet, meta)
			}
		}
		p.harness.recordLocked(flow, event)
	})
}

func (p *kernelTCPIO) rewriteSynOptions(packet []byte) {
	if !p.harness.config.disableSACK && !p.harness.config.disableTimestamps {
		return
	}
	parsed, valid := parseForwardPacket(packet)
	if !valid || !parsed.isPureTCPSyn() {
		return
	}
	tcp := header.TCP(parsed.transport)
	options := tcp.Options()
	for index := 0; index < len(options); {
		kind := options[index]
		if kind == header.TCPOptionEOL {
			break
		}
		if kind == header.TCPOptionNOP {
			index++
			continue
		}
		if index+1 >= len(options) {
			break
		}
		length := int(options[index+1])
		if length < 2 || index+length > len(options) {
			break
		}
		if kind == header.TCPOptionSACKPermitted && p.harness.config.disableSACK || kind == header.TCPOptionTS && p.harness.config.disableTimestamps {
			for offset := index; offset < index+length; offset++ {
				options[offset] = header.TCPOptionNOP
			}
		}
		index += length
	}
	var source, destination []byte
	if parsed.ipVersion == 4 {
		ip := header.IPv4(packet)
		source, destination = ip.SourceAddressSlice(), ip.DestinationAddressSlice()
	} else {
		ip := header.IPv6(packet)
		source, destination = ip.SourceAddressSlice(), ip.DestinationAddressSlice()
	}
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, destination, uint16(len(tcp)))
	tcp.SetChecksum(0)
	tcp.SetChecksum(^checksum.Checksum(tcp, pseudo))
}
