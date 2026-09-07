package tun

import (
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	goSocketEventBatch  = 64
	goSplicePacketBurst = 16
	goSpliceTokenShift  = 8
	goSpliceReadChunk   = 2 * goSlabSize
)

type SpliceSocket interface {
	syscall.Conn
	Attach(closer io.Closer) bool
	Detach()
}

type SpliceOptions struct {
	ReadCounters  []N.CountFunc
	WriteCounters []N.CountFunc
	OnClose       N.CloseHandlerFunc
}

type PacketNAT struct {
	Origin         M.Socksaddr
	Destination    M.Socksaddr
	FakeIP         bool
	Unidirectional bool
}

type SplicePacketOptions struct {
	SpliceOptions
	Timeout time.Duration
	NAT     PacketNAT
	Cached  []*N.PacketBuffer
}

type goSpliceSlot struct {
	stream     *GoConn
	packet     *GoPacketConn
	generation uint32
}

func (e *goEngine) allocateSpliceToken(stream *GoConn, packet *GoPacketConn) uint32 {
	var index uint32
	if free := len(e.spliceFree); free > 0 {
		index = e.spliceFree[free-1]
		e.spliceFree = e.spliceFree[:free-1]
	} else {
		index = uint32(len(e.spliceSlots))
		e.spliceSlots = append(e.spliceSlots, goSpliceSlot{})
	}
	slot := &e.spliceSlots[index]
	slot.generation = (slot.generation + 1) & (1<<goSpliceTokenShift - 1)
	slot.stream = stream
	slot.packet = packet
	return index<<goSpliceTokenShift | slot.generation
}

func (e *goEngine) releaseSpliceToken(token uint32) {
	index := token >> goSpliceTokenShift
	slot := &e.spliceSlots[index]
	slot.stream = nil
	slot.packet = nil
	e.spliceFree = append(e.spliceFree, index)
}

func (e *goEngine) spliceSlot(token uint32) *goSpliceSlot {
	index := token >> goSpliceTokenShift
	if index >= uint32(len(e.spliceSlots)) {
		return nil
	}
	slot := &e.spliceSlots[index]
	if slot.generation != token&(1<<goSpliceTokenShift-1) {
		return nil
	}
	return slot
}

func (e *goEngine) dispatchSocketEvents(count int) {
	for index := range count {
		event := e.socketEvents[index]
		slot := e.spliceSlot(event.token)
		if slot == nil {
			continue
		}
		if slot.stream != nil {
			e.handleStreamEvent(slot.stream, event)
		} else if slot.packet != nil {
			e.handlePacketEvent(slot.packet, event)
		}
	}
}

func goCount(counters []N.CountFunc, n int) {
	for _, counter := range counters {
		counter(int64(n))
	}
}

type goSpliceStream struct {
	conn           *GoConn
	owner          SpliceSocket
	socket         goSocket
	token          uint32
	interest       uint8
	options        SpliceOptions
	dirtyNext      *GoConn
	dirty          bool
	blocked        bool
	readStalled    bool
	uploadClosed   bool
	downloadClosed bool
}

func (c *GoConn) Splice(owner SpliceSocket, options SpliceOptions) bool {
	if c.connState.Load() != goConnStateEstablished {
		return false
	}
	socket, err := goSpliceSocket(owner)
	if err != nil {
		c.engine.stack.logger.Debug(E.Cause(err, "go: splice ", c.destination))
		return false
	}
	splice := &goSpliceStream{conn: c, owner: owner, socket: socket, options: options}
	if !owner.Attach(splice) {
		return false
	}
	if !c.splicePending.CompareAndSwap(nil, splice) {
		owner.Detach()
		return false
	}
	c.engine.postMessage(&c.spliceMessage)
	return true
}

func (s *goSpliceStream) Close() error {
	s.conn.requestAbort(net.ErrClosed)
	return nil
}

func (e *goEngine) handleSpliceEngage(conn *GoConn) {
	splice := conn.splicePending.Load()
	if splice == nil {
		return
	}
	if conn.splice != nil {
		conn.splicePending.Store(nil)
		e.spliceRelease(splice, net.ErrClosed)
		return
	}
	if conn.connState.Load() >= goConnStateAborted {
		conn.splicePending.Store(nil)
		e.spliceRelease(splice, conn.closeError())
		return
	}
	splice.token = e.allocateSpliceToken(conn, nil)
	err := e.platformIO.registerSocket(&splice.socket, splice.token, goInterestRead)
	if err != nil {
		conn.splicePending.Store(nil)
		e.releaseSpliceToken(splice.token)
		e.spliceRelease(splice, err)
		e.spliceAbort(conn, err)
		return
	}
	splice.interest = goInterestRead
	conn.splice = splice
	conn.spliced.Store(true)
	conn.splicePending.Store(nil)
	e.spliceFlushUpload(conn)
	if conn.splice == nil {
		return
	}
	e.spliceReadPeer(conn)
}

func (e *goEngine) spliceRelease(splice *goSpliceStream, err error) {
	splice.owner.Detach()
	if splice.options.OnClose != nil {
		splice.options.OnClose(err)
	}
}

func (e *goEngine) spliceDetach(conn *GoConn, err error) {
	pending := conn.splicePending.Swap(nil)
	if pending != nil {
		e.spliceRelease(pending, err)
	}
	splice := conn.splice
	if splice == nil {
		return
	}
	if splice.dirty {
		e.spliceUnlinkDirty(conn)
	}
	conn.splice = nil
	conn.spliced.Store(false)
	e.platformIO.unregisterSocket(&splice.socket)
	e.releaseSpliceToken(splice.token)
	e.spliceRelease(splice, err)
}

func (e *goEngine) spliceUnlinkDirty(conn *GoConn) {
	splice := conn.splice
	splice.dirty = false
	if e.spliceDirtyList == conn {
		e.spliceDirtyList = splice.dirtyNext
		splice.dirtyNext = nil
		return
	}
	for previous := e.spliceDirtyList; previous != nil; previous = previous.splice.dirtyNext {
		if previous.splice.dirtyNext == conn {
			previous.splice.dirtyNext = splice.dirtyNext
			splice.dirtyNext = nil
			return
		}
	}
}

func (e *goEngine) spliceAbort(conn *GoConn, err error) {
	e.sendReset(conn)
	e.detachConn(conn, err, goDeathAbortLinger)
}

func (e *goEngine) spliceSetInterest(conn *GoConn, interest uint8) {
	splice := conn.splice
	if splice.interest == interest {
		return
	}
	splice.interest = interest
	err := e.platformIO.updateSocket(&splice.socket, interest)
	if err != nil {
		e.spliceAbort(conn, err)
	}
}

func (e *goEngine) handleStreamEvent(conn *GoConn, event goSocketEvent) {
	if event.writable && conn.splice != nil {
		conn.splice.blocked = false
		e.spliceFlushUpload(conn)
	}
	if event.readable && conn.splice != nil {
		e.spliceReadPeer(conn)
	}
}

func (e *goEngine) spliceDeliver(conn *GoConn, data []byte) {
	conn.receiveChain.reserve(conn.receiveNext, len(data))
	conn.receiveChain.writeAt(conn.receiveNext, data)
	conn.receiveNext += uint64(len(data))
	conn.receiveNextAck.Store(conn.receiveNext)
	conn.receiveAvailable.Store(conn.receiveNext)
	conn.publishReceiveWindow()
	e.spliceMarkDirty(conn)
}

func (e *goEngine) spliceMarkDirty(conn *GoConn) {
	splice := conn.splice
	if splice.dirty {
		return
	}
	splice.dirty = true
	splice.dirtyNext = e.spliceDirtyList
	e.spliceDirtyList = conn
}

func (e *goEngine) flushSpliceDirty() {
	for conn := e.spliceDirtyList; conn != nil; {
		splice := conn.splice
		next := splice.dirtyNext
		splice.dirtyNext = nil
		splice.dirty = false
		e.spliceFlushUpload(conn)
		conn = next
	}
	e.spliceDirtyList = nil
}

func (e *goEngine) spliceFlushUpload(conn *GoConn) {
	splice := conn.splice
	for !splice.blocked {
		consumed := conn.consumedTail.Load()
		available := conn.receiveAvailable.Load()
		if consumed >= available {
			break
		}
		e.spliceSegments = conn.receiveChain.appendRuns(e.spliceSegments[:0], consumed, int(available-consumed))
		e.spliceIovecs = goIovecsFromSegments(e.spliceIovecs, e.spliceSegments)
		n, errno := splice.socket.writeVector(e.spliceIovecs)
		switch {
		case errno == 0:
			consumed = conn.consumedTail.Add(uint64(n))
			goCount(splice.options.ReadCounters, n)
			if consumed < available {
				splice.blocked = true
			}
			if conn.windowUpdateDue(consumed) {
				e.handleWindowUpdate(conn)
			}
		case goSocketWouldBlock(errno):
			splice.blocked = true
		default:
			e.spliceAbort(conn, E.Cause(errno, "go: write peer"))
			return
		}
	}
	interest := splice.interest &^ goInterestWrite
	if splice.blocked {
		interest |= goInterestWrite
	}
	e.spliceSetInterest(conn, interest)
	if conn.splice != nil {
		e.spliceCheckUpload(conn)
	}
}

func (e *goEngine) spliceCheckUpload(conn *GoConn) {
	splice := conn.splice
	if splice.uploadClosed || !conn.finReceived || conn.receiveAvailable.Load() > conn.consumedTail.Load() {
		return
	}
	splice.socket.shutdownWrite()
	splice.uploadClosed = true
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceAfterInput(conn *GoConn) {
	splice := conn.splice
	if splice == nil {
		return
	}
	if conn.receiveAvailable.Load() > conn.consumedTail.Load() || (conn.finReceived && !splice.uploadClosed) {
		e.spliceMarkDirty(conn)
		return
	}
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceReadPeer(conn *GoConn) {
	splice := conn.splice
	for !splice.downloadClosed {
		budget := conn.writeBudget(0)
		if budget <= 0 {
			splice.readStalled = true
			e.spliceSetInterest(conn, splice.interest&^goInterestRead)
			return
		}
		budget = min(budget, goSpliceReadChunk)
		buffered := conn.bufferedTail.Load()
		conn.transmitStore.reserve(buffered, budget)
		e.spliceSegments = conn.transmitStore.chain.appendRuns(e.spliceSegments[:0], buffered, budget)
		e.spliceIovecs = goIovecsFromSegments(e.spliceIovecs, e.spliceSegments)
		n, errno := splice.socket.readVector(e.spliceIovecs)
		if errno != 0 || n < 0 {
			n = 0
		}
		if n < budget {
			conn.transmitStore.shrinkReserve(buffered + uint64(n))
		}
		switch {
		case errno == 0 && n == 0:
			splice.downloadClosed = true
			e.spliceSetInterest(conn, splice.interest&^goInterestRead)
			if conn.splice == nil {
				return
			}
			conn.finPending = true
		case errno == 0:
			conn.bufferedTail.Store(buffered + uint64(n))
			goCount(splice.options.WriteCounters, n)
			if !e.spliceTransmit(conn) {
				return
			}
		case goSocketWouldBlock(errno):
			e.spliceMaybeFinish(conn)
			return
		default:
			e.spliceAbort(conn, E.Cause(errno, "go: read peer"))
			return
		}
	}
	e.maybeSendFin(conn)
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceTransmit(conn *GoConn) bool {
	if conn.blockedValid || !conn.transmitOwner.CompareAndSwap(0, 1) {
		return true
	}
	_, blocked := conn.transmitLoop(false, 0)
	conn.transmitOwner.Store(0)
	if conn.connState.Load() >= goConnStateAborted {
		return false
	}
	if blocked {
		e.handleTransmitBlocked(conn)
	}
	return true
}

func (e *goEngine) spliceResume(conn *GoConn) {
	if !e.spliceTransmit(conn) {
		return
	}
	splice := conn.splice
	if splice == nil || !splice.readStalled || splice.downloadClosed || conn.writeBudget(0) <= 0 {
		return
	}
	splice.readStalled = false
	e.spliceSetInterest(conn, splice.interest|goInterestRead)
	if conn.splice != nil {
		e.spliceReadPeer(conn)
	}
}

func (e *goEngine) spliceRetryBlocked(conn *GoConn) {
	segment := conn.blockedSegment
	end := segment.offset + uint64(segment.length)
	err := conn.transmitFrame(&segment)
	switch err {
	case nil:
	case errGoTransmitBlocked:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorNoSample)
		e.handleTransmitBlocked(conn)
		return
	case errGoFrameDropped:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorDropped)
		conn.blockedValid = false
		conn.blockedFrame = nil
		conn.transmittedTail.Store(end)
		e.handleDroppedFrames(conn)
		return
	default:
		e.spliceAbort(conn, E.Cause(err, "go: write tun"))
		return
	}
	conn.blockedValid = false
	conn.blockedFrame = nil
	conn.transmittedTail.Store(end)
	e.spliceResume(conn)
	if conn.splice != nil && conn.splice.downloadClosed {
		e.maybeSendFin(conn)
		e.spliceMaybeFinish(conn)
	}
}

func (e *goEngine) spliceMaybeFinish(conn *GoConn) {
	splice := conn.splice
	if splice == nil || !splice.uploadClosed || !splice.downloadClosed || !conn.finSent {
		return
	}
	e.spliceDetach(conn, nil)
}

type goSplicePacket struct {
	writer      *GoPacketConn
	owner       SpliceSocket
	socket      goSocket
	token       uint32
	family      uint8
	connected   bool
	rewritePort bool
	finished    bool
	peer        netip.AddrPort
	origin      netip.AddrPort
	destination netip.AddrPort
	direct      map[netip.Addr]struct{}
	options     SplicePacketOptions
}

func (c *UDPNatConn) Splice(owner SpliceSocket, options SplicePacketOptions) bool {
	writer, isGoPacketConn := c.writer.(*GoPacketConn)
	if !isGoPacketConn || writer.conn.Load() != c {
		return false
	}
	return writer.spliceTo(owner, options)
}

func (w *GoPacketConn) spliceTo(owner SpliceSocket, options SplicePacketOptions) bool {
	if options.NAT.Origin.IsValid() && (!options.NAT.Origin.IsIP() || !options.NAT.Destination.IsIP()) {
		return false
	}
	socket, err := goSpliceSocket(owner)
	if err != nil {
		w.engine.stack.logger.Debug(E.Cause(err, "go: splice packet connection"))
		return false
	}
	family, err := socket.family()
	if err != nil {
		return false
	}
	splice := &goSplicePacket{writer: w, owner: owner, socket: socket, family: family, options: options}
	splice.peer, splice.connected = socket.peerAddress()
	if options.NAT.Origin.IsValid() {
		splice.origin = options.NAT.Origin.AddrPort()
		splice.destination = options.NAT.Destination.AddrPort()
		splice.rewritePort = splice.origin.Port() != splice.destination.Port()
	}
	if !owner.Attach(splice) {
		return false
	}
	if !w.splicePending.CompareAndSwap(nil, splice) {
		owner.Detach()
		return false
	}
	w.engine.postMessage(&w.spliceMessage)
	return true
}

func (s *goSplicePacket) Close() error {
	s.writer.closeSplice(net.ErrClosed)
	return nil
}

func (w *GoPacketConn) closeSplice(err error) {
	w.spliceCloseError.CompareAndSwap(nil, &goConnError{err: err})
	w.engine.postMessage(&w.closeMessage)
}

func (w *GoPacketConn) Close() error {
	if w.splicePending.Load() != nil || w.spliceActive.Load() {
		w.closeSplice(io.ErrClosedPipe)
	}
	return nil
}

func (e *goEngine) handlePacketSpliceEngage(w *GoPacketConn) {
	splice := w.splicePending.Load()
	if splice == nil {
		return
	}
	if w.splice != nil {
		w.splicePending.Store(nil)
		e.packetSpliceRelease(splice, net.ErrClosed)
		return
	}
	natConn := w.conn.Load()
	if natConn == nil || natConn.isClosed() {
		w.splicePending.Store(nil)
		e.packetSpliceRelease(splice, io.ErrClosedPipe)
		return
	}
	if splice.options.Timeout > 0 {
		current := natConn.Timeout()
		if !(current > 0 && splice.options.Timeout >= current) && !natConn.SetTimeout(splice.options.Timeout) {
			w.splicePending.Store(nil)
			e.packetSpliceRelease(splice, io.ErrClosedPipe)
			return
		}
	}
	splice.token = e.allocateSpliceToken(nil, w)
	err := e.platformIO.registerSocket(&splice.socket, splice.token, goInterestRead)
	if err != nil {
		w.splicePending.Store(nil)
		e.releaseSpliceToken(splice.token)
		e.packetSpliceRelease(splice, err)
		natConn.Close()
		return
	}
	w.splice = splice
	w.spliceActive.Store(true)
	w.splicePending.Store(nil)
	cached := splice.options.Cached
	splice.options.Cached = nil
	for _, packet := range cached {
		if w.splice != nil {
			e.packetSpliceUpload(w, packet.Buffer.Bytes(), packet.Destination)
		}
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
	for w.splice != nil {
		select {
		case packet := <-natConn.packetChan:
			e.packetSpliceUpload(w, packet.Buffer.Bytes(), packet.Destination)
			packet.Buffer.Release()
			N.PutPacketBuffer(packet)
		default:
			e.packetSpliceRead(w)
			return
		}
	}
}

func (e *goEngine) packetSpliceRelease(splice *goSplicePacket, err error) {
	splice.finished = true
	N.ReleaseMultiPacketBuffer(splice.options.Cached)
	splice.options.Cached = nil
	splice.owner.Detach()
	if splice.options.OnClose != nil {
		splice.options.OnClose(err)
	}
}

func (e *goEngine) handlePacketSpliceClose(w *GoPacketConn) {
	var err error
	closeError := w.spliceCloseError.Load()
	if closeError != nil {
		err = closeError.err
	}
	pending := w.splicePending.Swap(nil)
	if pending != nil {
		e.packetSpliceRelease(pending, err)
	}
	if w.splice == nil {
		return
	}
	e.packetSpliceClose(w, err)
}

func (e *goEngine) packetSpliceClose(w *GoPacketConn, err error) {
	splice := w.splice
	w.splice = nil
	w.spliceActive.Store(false)
	e.platformIO.unregisterSocket(&splice.socket)
	e.releaseSpliceToken(splice.token)
	natConn := w.conn.Load()
	if natConn != nil {
		natConn.Close()
	}
	e.packetSpliceRelease(splice, err)
}

func (e *goEngine) releasePendingSplice(message *goMessage) {
	switch message.kind {
	case goMessageConnSplice:
		pending := message.conn.splicePending.Swap(nil)
		if pending != nil {
			e.spliceRelease(pending, net.ErrClosed)
		}
	case goMessagePacketSplice:
		pending := message.packet.splicePending.Swap(nil)
		if pending != nil {
			e.packetSpliceRelease(pending, net.ErrClosed)
		}
	}
}

func (e *goEngine) closeAllPacketSplices() {
	for index := range e.spliceSlots {
		packet := e.spliceSlots[index].packet
		if packet != nil && packet.splice != nil {
			e.packetSpliceClose(packet, net.ErrClosed)
		}
	}
}

func (s *goSplicePacket) mapUpload(destination netip.AddrPort) netip.AddrPort {
	if s.origin.IsValid() && destination.Addr() == s.origin.Addr() {
		if !s.rewritePort {
			return netip.AddrPortFrom(s.destination.Addr(), destination.Port())
		}
		if destination.Port() == s.origin.Port() {
			return s.destination
		}
	}
	if s.options.NAT.FakeIP && destination.Addr().IsValid() {
		if s.direct == nil {
			s.direct = make(map[netip.Addr]struct{})
		}
		s.direct[destination.Addr()] = struct{}{}
	}
	return destination
}

func (s *goSplicePacket) mapDownload(source netip.AddrPort) netip.AddrPort {
	if s.options.NAT.Unidirectional {
		return source
	}
	if s.origin.IsValid() && source.Addr() == s.destination.Addr() {
		if !s.rewritePort {
			return netip.AddrPortFrom(s.origin.Addr(), source.Port())
		}
		if source.Port() == s.destination.Port() {
			return s.origin
		}
	}
	if s.options.NAT.FakeIP {
		_, direct := s.direct[source.Addr()]
		if !direct {
			return netip.AddrPortFrom(s.origin.Addr(), source.Port())
		}
	}
	return source
}

func (e *goEngine) packetSpliceUpload(w *GoPacketConn, payload []byte, destination M.Socksaddr) {
	splice := w.splice
	target := splice.mapUpload(destination.AddrPort())
	var errno syscall.Errno
	if splice.connected {
		_, errno = splice.socket.write(payload)
	} else {
		errno = splice.socket.sendTo(payload, target, splice.family)
	}
	if errno != 0 {
		if goSocketWouldBlock(errno) || goSocketDropped(errno) {
			return
		}
		e.packetSpliceClose(w, E.Cause(errno, "go: send peer"))
		return
	}
	goCount(splice.options.ReadCounters, len(payload))
}

func (e *goEngine) handlePacketEvent(w *GoPacketConn, event goSocketEvent) {
	if event.readable && w.splice != nil {
		e.packetSpliceRead(w)
	}
}

func (e *goEngine) packetReceiveBuffer() *buf.Buffer {
	if e.packetReceive == nil {
		headroom := e.platformIO.transmitPrefix() + header.IPv6MinimumSize + header.UDPMinimumSize
		e.packetReceive = buf.With(make([]byte, headroom+0xffff))
	}
	return e.packetReceive
}

func (e *goEngine) packetSpliceRead(w *GoPacketConn) {
	splice := w.splice
	natConn := w.conn.Load()
	buffer := e.packetReceiveBuffer()
	headroom := e.platformIO.transmitPrefix() + header.IPv6MinimumSize + header.UDPMinimumSize
	for range goSplicePacketBurst {
		buffer.Resize(headroom, 0)
		n, source, errno := splice.socket.receiveFrom(buffer.FreeBytes())
		if errno != 0 {
			if goSocketWouldBlock(errno) {
				return
			}
			e.packetSpliceClose(w, E.Cause(errno, "go: receive peer"))
			return
		}
		buffer.Truncate(n)
		if !source.IsValid() {
			source = splice.peer
		}
		destination := M.SocksaddrFromNetIP(splice.mapDownload(source))
		if !natConn.allowPeer(destination) {
			continue
		}
		goCount(splice.options.WriteCounters, n)
		err := w.transmit(buffer, destination)
		if err != nil {
			e.stack.logger.Trace(E.Cause(err, "go: write spliced packet"))
		}
	}
}

func (e *goEngine) reclaimPacketReceive() {
	for index := range e.spliceSlots {
		if e.spliceSlots[index].packet != nil {
			return
		}
	}
	e.packetReceive = nil
}
