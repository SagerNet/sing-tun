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
	goSocketEventBatch = 64
	goSpliceTokenShift = 8
	goSpliceReadChunk  = 2 * goSlabSize
)

type SpliceSocket interface {
	syscall.Conn
	io.Closer
	Attach(closer io.Closer) (io.Closer, bool)
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
	Timeout       time.Duration
	NAT           PacketNAT
	Cached        []*N.PacketBuffer
	Offload       N.PacketOffload
	FrontHeadroom int
	RearHeadroom  int
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
		} else if slot.packet != nil && event.readable && slot.packet.splice != nil {
			e.packetSpliceRead(slot.packet)
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
	original       io.Closer
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
	splice := &goSpliceStream{conn: c, owner: owner, options: options}
	original, attached := owner.Attach(splice)
	if !attached {
		return false
	}
	splice.original = original
	socket, err := goSpliceSocket(owner)
	if err != nil {
		owner.Detach()
		c.engine.stack.logger.Debug(E.Cause(err, "go: splice ", c.destination))
		return false
	}
	splice.socket = socket
	if !c.splicePending.CompareAndSwap(nil, splice) {
		socket.close()
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
	var err error
	if goSpliceDuplicatesSocket {
		err = splice.original.Close()
	}
	if err == nil {
		err = e.platformIO.registerSocket(&splice.socket, splice.token, goInterestRead)
	}
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
}

func (e *goEngine) spliceRelease(splice *goSpliceStream, err error) {
	splice.socket.close()
	splice.owner.Detach()
	splice.owner.Close()
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
	if conn.connState.Load() >= goConnStateDead {
		conn.storeError(err)
		conn.receiveDrainable.Store(false)
		e.spliceDetach(conn, err)
		return
	}
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
	consumed := conn.consumedTail.Load()
	conn.receiveChain.releaseBelow(consumed)
	if consumed == conn.receiveAvailable.Load() && (conn.oooRanges == nil || conn.oooRanges.count == 0) {
		conn.receiveChain.releaseDrained(consumed)
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
	// Empty speculative reads must not keep the partial tail slab while the
	// socket is waiting. Unacknowledged and out-of-order data remain retained.
	defer conn.releaseDrainedSlabs()
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

type goPacketMessage struct {
	data          []byte
	destination   netip.AddrPort
	segmentSize   int
	truncated     bool
	payloadLength int
}

type goPacketUpload struct {
	message goPacketMessage
	next    int
}

type goSplicePacket struct {
	writer      *GoPacketConn
	owner       SpliceSocket
	original    io.Closer
	socket      goSocket
	token       uint32
	family      uint8
	connected   bool
	rewritePort bool
	finished    bool
	peer        netip.AddrPort
	origin      M.Socksaddr
	destination M.Socksaddr
	direct      map[netip.Addr]struct{}
	options     SplicePacketOptions
	uploadHead  int
	uploadTail  int
	nextDirty   *goSplicePacket
}

func (c *UDPNatConn) Splice(owner SpliceSocket, options SplicePacketOptions) bool {
	writer, isGoPacketConn := c.writer.(*GoPacketConn)
	if !isGoPacketConn || writer.conn.Load() != c {
		return false
	}
	return writer.spliceTo(owner, options)
}

func (w *GoPacketConn) spliceTo(owner SpliceSocket, options SplicePacketOptions) bool {
	if options.NAT.Origin.IsValid() && (!options.NAT.Origin.IsIP() || !options.NAT.Destination.IsIP() && options.Offload == nil) {
		return false
	}
	splice := &goSplicePacket{writer: w, owner: owner, options: options, uploadHead: -1, uploadTail: -1}
	original, attached := owner.Attach(splice)
	if !attached {
		return false
	}
	splice.original = original
	socket, err := goSpliceSocket(owner)
	if err != nil {
		owner.Detach()
		w.engine.stack.logger.Debug(E.Cause(err, "go: splice packet connection"))
		return false
	}
	family, err := socket.family()
	if err != nil {
		socket.close()
		owner.Detach()
		return false
	}
	splice.socket = socket
	splice.family = family
	splice.peer, splice.connected = socket.peerAddress()
	if options.Offload != nil && !splice.connected {
		socket.close()
		owner.Detach()
		return false
	}
	if options.NAT.Origin.IsValid() {
		splice.origin = options.NAT.Origin
		splice.destination = options.NAT.Destination
		splice.rewritePort = splice.origin.Port != splice.destination.Port
	}
	if !w.splicePending.CompareAndSwap(nil, splice) {
		socket.close()
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
	closeError := w.spliceCloseError.Load()
	if closeError != nil {
		w.splicePending.Store(nil)
		e.packetSpliceRelease(splice, closeError.err)
		natConn.Close()
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
	var err error
	if goSpliceDuplicatesSocket {
		err = splice.original.Close()
	}
	if err == nil {
		err = e.platformIO.registerSocket(&splice.socket, splice.token, goInterestRead)
	}
	if err != nil {
		w.splicePending.Store(nil)
		e.releaseSpliceToken(splice.token)
		e.packetSpliceRelease(splice, err)
		natConn.Close()
		return
	}
	w.splice = splice
	splice.socket.enablePacketOffload()
	w.spliceActive.Store(true)
	w.splicePending.Store(nil)
	readOptions := N.ReadWaitOptions{
		FrontHeadroom: splice.options.FrontHeadroom,
		RearHeadroom:  splice.options.RearHeadroom,
	}
	e.updatePacketHeadroom(readOptions)
	cached := splice.options.Cached
	splice.options.Cached = nil
	for _, packet := range cached {
		if w.splice != nil {
			packet.Buffer = readOptions.Copy(packet.Buffer)
			e.packetSpliceUpload(w, packet.Buffer, packet.Destination)
			e.flushPacketUploads()
		}
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
	for w.splice != nil {
		select {
		case packet := <-natConn.packetChan:
			packet.Buffer = readOptions.Copy(packet.Buffer)
			e.packetSpliceUpload(w, packet.Buffer, packet.Destination)
			e.flushPacketUploads()
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
	splice.socket.close()
	splice.owner.Detach()
	splice.owner.Close()
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

func (e *goEngine) releasePending(message *goMessage) {
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
	case goMessageInject:
		e.releaseInjected()
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

func (s *goSplicePacket) mapUpload(destination M.Socksaddr) M.Socksaddr {
	if s.origin.IsValid() && destination.Addr == s.origin.Addr {
		if !s.rewritePort {
			return M.Socksaddr{Addr: s.destination.Addr, Fqdn: s.destination.Fqdn, Port: destination.Port}
		}
		if destination.Port == s.origin.Port {
			return s.destination
		}
	}
	if s.options.NAT.FakeIP && destination.IsIP() {
		if s.direct == nil {
			s.direct = make(map[netip.Addr]struct{})
		}
		s.direct[destination.Addr] = struct{}{}
	}
	return destination
}

func (s *goSplicePacket) mapDownload(source M.Socksaddr) M.Socksaddr {
	if s.options.NAT.Unidirectional {
		return source
	}
	if s.origin.IsValid() && source.Addr == s.destination.Addr && (s.destination.IsIP() || source.Fqdn == s.destination.Fqdn) {
		if !s.rewritePort {
			return M.Socksaddr{Addr: s.origin.Addr, Port: source.Port}
		}
		if source.Port == s.destination.Port {
			return s.origin
		}
	}
	if s.options.NAT.FakeIP {
		_, direct := s.direct[source.Addr]
		if !direct {
			return M.Socksaddr{Addr: s.origin.Addr, Port: source.Port}
		}
	}
	return source
}

func (e *goEngine) packetSpliceUpload(w *GoPacketConn, buffer *buf.Buffer, destination M.Socksaddr) {
	splice := w.splice
	target := splice.mapUpload(destination)
	payloadLength := buffer.Len()
	if splice.options.Offload != nil {
		err := splice.options.Offload.EncodePacket(buffer, target)
		if err != nil {
			e.packetSpliceClose(w, E.Cause(err, "go: encode packet"))
			return
		}
	}
	e.queuePacketUpload(splice, buffer.Bytes(), target.AddrPort(), payloadLength)
}

func (e *goEngine) updatePacketHeadroom(options N.ReadWaitOptions) {
	previous := *e.packetReadOptions.Load()
	options.FrontHeadroom = max(previous.FrontHeadroom, options.FrontHeadroom-header.IPv4MinimumSize-header.UDPMinimumSize)
	options.RearHeadroom = max(previous.RearHeadroom, options.RearHeadroom)
	if options == previous {
		return
	}
	e.flushPacketUploads()
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if !entry.active {
			continue
		}
		buffer := buf.NewSize(options.FrontHeadroom + goReassemblyCapacity + options.RearHeadroom)
		copy(buffer.FreeBytes()[options.FrontHeadroom:], entry.buffer.Range(entry.headroom-goReassemblyHeadroom, entry.headroom+65535))
		entry.buffer.Release()
		entry.buffer = buffer
		entry.headroom = options.FrontHeadroom + goReassemblyHeadroom
	}
	clear(e.frames)
	e.udpUserData.packet = nil
	e.packetReadOptions.Store(&options)
}

func (e *goEngine) packetSpliceRead(w *GoPacketConn) {
	splice := w.splice
	natConn := w.conn.Load()
	batchSize := e.packetReceiveBatch
	for index := range batchSize {
		buffer := e.packetReceiveBuffers[index]
		if buffer == nil {
			buffer = buf.NewSize(65535)
			e.packetReceiveBuffers[index] = buffer
		}
		buffer.Reset()
		e.packetMessages[index] = goPacketMessage{data: buffer.FreeBytes()}
	}
	count, errno := e.packetIO.receive(&splice.socket, e.packetMessages[:batchSize], splice.connected)
	if count == batchSize {
		e.packetReceiveBatch = min(batchSize*2, goPacketBatchSize)
	} else if count*2 < batchSize {
		e.packetReceiveBatch = max(batchSize/2, goReceiveBatchMin)
	}
	defer func() {
		e.flushPacketFrames()
		clear(e.packetMessages[:])
		if errno != 0 && !goSocketWouldBlock(errno) && w.splice != nil {
			e.packetSpliceClose(w, E.Cause(errno, "go: receive peer batch"))
		}
	}()
	for index := range count {
		message := e.packetMessages[index]
		if message.truncated {
			continue
		}
		buffer := e.packetReceiveBuffers[index]
		offset := 0
		for {
			length := len(message.data) - offset
			if message.segmentSize > 0 {
				length = min(length, message.segmentSize)
			}
			buffer.Resize(offset, length)
			var destination M.Socksaddr
			if splice.options.Offload != nil {
				packetSource, err := splice.options.Offload.DecodePacket(buffer)
				if err != nil {
					e.packetSpliceClose(w, E.Cause(err, "go: decode packet"))
					return
				}
				destination = splice.mapDownload(packetSource.Unwrap())
			} else {
				source := message.destination
				if !source.IsValid() {
					source = splice.peer
				}
				destination = splice.mapDownload(M.SocksaddrFromNetIP(source))
			}
			if destination.IsIP() && natConn.allowPeer(destination) {
				goCount(splice.options.WriteCounters, buffer.Len())
				e.packetSpliceDownload(w, buffer.Bytes(), destination)
			}
			offset += length
			if offset == len(message.data) {
				break
			}
		}
	}
}

func (e *goEngine) flushPacketUploads() {
	for e.packetDirtyList != nil {
		splice := e.packetDirtyList
		e.packetDirtyList = splice.nextDirty
		splice.nextDirty = nil
		count := 0
		for index := splice.uploadHead; index >= 0; index = e.packetUploads[index].next {
			upload := &e.packetUploads[index]
			e.packetMessages[count] = upload.message
			count++
		}
		splice.uploadHead = -1
		splice.uploadTail = -1
		if !splice.finished {
			sent, errno := e.packetIO.send(&splice.socket, e.packetMessages[:count], splice.connected, splice.family)
			length := 0
			for index := range sent {
				length += e.packetMessages[index].payloadLength
			}
			goCount(splice.options.ReadCounters, length)
			if errno != 0 && !goSocketWouldBlock(errno) && !goSocketDropped(errno) {
				e.packetSpliceClose(splice.writer, E.Cause(errno, "go: send peer batch"))
			}
		}
		clear(e.packetMessages[:count])
	}
	clear(e.packetUploads[:e.packetUploadCount])
	e.packetUploadCount = 0
}

func (e *goEngine) queuePacketUpload(splice *goSplicePacket, data []byte, destination netip.AddrPort, length int) {
	if e.packetUploadCount == len(e.packetUploads) {
		e.flushPacketUploads()
		if splice.finished {
			return
		}
	}
	index := e.packetUploadCount
	e.packetUploadCount++
	e.packetUploads[index] = goPacketUpload{
		message: goPacketMessage{data: data, destination: destination, payloadLength: length},
		next:    -1,
	}
	if splice.uploadHead < 0 {
		splice.uploadHead = index
		splice.nextDirty = e.packetDirtyList
		e.packetDirtyList = splice
	} else {
		e.packetUploads[splice.uploadTail].next = index
	}
	splice.uploadTail = index
}

func (e *goEngine) flushPacketFrames() {
	if e.packetFrameCount == 0 {
		return
	}
	err := e.platformIO.writePacketBatch(e.packetFrames[:e.packetFrameCount])
	if err != nil && err != errGoFrameDropped {
		e.stack.logger.Trace(E.Cause(err, "go: write packet batch"))
	}
	clear(e.packetFrames[:e.packetFrameCount])
	e.packetFrameCount = 0
}

func (e *goEngine) packetSpliceDownload(w *GoPacketConn, data []byte, destination M.Socksaddr) {
	if len(data)+w.templateLength > w.mtu {
		e.flushPacketFrames()
		buffer := buf.NewSize(w.FrontHeadroom() + len(data))
		buffer.Resize(w.FrontHeadroom(), 0)
		copy(buffer.Extend(len(data)), data)
		err := w.transmit(buffer, destination)
		buffer.Release()
		if err != nil {
			e.stack.logger.Trace(E.Cause(err, "go: write fragmented packet"))
		}
		return
	}
	frame := &e.packetFrames[e.packetFrameCount]
	meta, err := w.preparePacketHeader(frame.header[:], data, destination, w.checksumOffload)
	if err != nil {
		if err != errGoFrameDropped {
			e.stack.logger.Trace(err)
		}
		return
	}
	frame.length = w.templateLength
	frame.payload = data
	frame.meta = meta
	e.packetFrameCount++
	if e.packetFrameCount == len(e.packetFrames) {
		e.flushPacketFrames()
	}
}
