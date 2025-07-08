// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fdbased

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/stack/gro"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
	"github.com/metacubex/sing-tun/internal/stopfd_darwin"

	"golang.org/x/sys/unix"
)

// BufConfig defines the shape of the buffer used to read packets from the NIC.
var BufConfig = []int{4, 128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

// +stateify savable
type iovecBuffer struct {
	// buffer is the actual buffer that holds the packet contents. Some contents
	// are reused across calls to pullBuffer if number of requested bytes is
	// smaller than the number of bytes allocated in the buffer.
	views []*buffer.View

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled
	// (skipsVnetHdr) then the first iovec points to a buffer for the vnet header
	// which is stripped before the views are passed up the stack for further
	// processing.
	iovecs []unix.Iovec `state:"nosave"`

	// sizes is an array of buffer sizes for the underlying views. sizes is
	// immutable.
	sizes []int

	// pulledIndex is the index of the last []byte buffer pulled from the
	// underlying buffer storage during a call to pullBuffers. It is -1
	// if no buffer is pulled.
	pulledIndex int
}

func newIovecBuffer(sizes []int) *iovecBuffer {
	b := &iovecBuffer{
		views:  make([]*buffer.View, len(sizes)),
		iovecs: make([]unix.Iovec, len(sizes)),
		sizes:  sizes,
	}
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	for i := range b.views {
		if b.views[i] != nil {
			break
		}
		v := buffer.NewViewSize(b.sizes[i])
		b.views[i] = v
		b.iovecs[i] = unix.Iovec{Base: v.BasePtr()}
		b.iovecs[i].SetLen(v.Size())
	}
	return b.iovecs
}

// pullBuffer extracts the enough underlying storage from b.buffer to hold n
// bytes. It removes this storage from b.buffer, returns a new buffer
// that holds the storage, and updates pulledIndex to indicate which part
// of b.buffer's storage must be reallocated during the next call to
// nextIovecs.
func (b *iovecBuffer) pullBuffer(n int) buffer.Buffer {
	var views []*buffer.View
	c := 0
	// Remove the used views from the buffer.
	for i, v := range b.views {
		c += v.Size()
		if c >= n {
			b.views[i].CapLength(v.Size() - (c - n))
			views = append(views, b.views[:i+1]...)
			break
		}
	}
	for i := range views {
		b.views[i] = nil
	}
	pulled := buffer.Buffer{}
	for _, v := range views {
		pulled.Append(v)
	}
	pulled.Truncate(int64(n))
	return pulled
}

func (b *iovecBuffer) release() {
	for _, v := range b.views {
		if v != nil {
			v.Release()
			v = nil
		}
	}
}

// recvMMsgDispatcher uses the recvmmsg system call to read inbound packets and
// dispatches them.
//
// +stateify savable
type recvMMsgDispatcher struct {
	stopfd.StopFD
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// bufs is an array of iovec buffers that contain packet contents.
	bufs []*iovecBuffer

	// msgHdrs is an array of MMsgHdr objects where each MMsghdr is used to
	// reference an array of iovecs in the iovecs field defined above.  This
	// array is passed as the parameter to recvmmsg call to retrieve
	// potentially more than 1 packet per unix.
	msgHdrs []rawfile.MsgHdrX `state:"nosave"`

	// pkts is reused to avoid allocations.
	pkts stack.PacketBufferList

	// gro coalesces incoming packets to increase throughput.
	gro gro.GRO

	// mgr is the processor goroutine manager.
	mgr *processorManager
}

func newRecvMMsgDispatcher(fd int, e *endpoint, opts *Options) (linkDispatcher, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	batchSize := int((512*1024)/(opts.MTU)) + 1
	d := &recvMMsgDispatcher{
		StopFD:  stopFD,
		fd:      fd,
		e:       e,
		bufs:    make([]*iovecBuffer, batchSize),
		msgHdrs: make([]rawfile.MsgHdrX, batchSize),
	}
	bufConfig := []int{4, int(opts.MTU)}
	for i := range d.bufs {
		d.bufs[i] = newIovecBuffer(bufConfig)
	}
	d.gro.Init(false)
	d.mgr = newProcessorManager(opts, e)
	d.mgr.start()

	return d, nil
}

func (d *recvMMsgDispatcher) release() {
	for _, iov := range d.bufs {
		iov.release()
	}
	d.mgr.close()
}

// recvMMsgDispatch reads more than one packet at a time from the file
// descriptor and dispatches it.
func (d *recvMMsgDispatcher) dispatch() (bool, tcpip.Error) {
	// Fill message headers.
	for k := range d.msgHdrs {
		if d.msgHdrs[k].Msg.Iovlen > 0 {
			break
		}
		iovecs := d.bufs[k].nextIovecs()
		iovLen := len(iovecs)
		d.msgHdrs[k].DataLen = 0
		d.msgHdrs[k].Msg.Iov = &iovecs[0]
		d.msgHdrs[k].Msg.SetIovlen(iovLen)
	}

	nMsgs, errno := rawfile.BlockingRecvMMsgUntilStopped(d.ReadFD, d.fd, d.msgHdrs)
	if errno != 0 {
		return false, TranslateErrno(errno)
	}
	if nMsgs == -1 {
		return false, nil
	}

	// Process each of received packets.

	d.e.mu.RLock()
	addr := d.e.addr
	dsp := d.e.dispatcher
	d.e.mu.RUnlock()

	d.gro.Dispatcher = dsp
	defer d.pkts.Reset()

	for k := 0; k < nMsgs; k++ {
		n := int(d.msgHdrs[k].DataLen)
		payload := d.bufs[k].pullBuffer(n)
		payload.TrimFront(4)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		d.pkts.PushBack(pkt)

		// Mark that this iovec has been processed.
		d.msgHdrs[k].Msg.Iovlen = 0

		if d.e.parseInboundHeader(pkt, addr) {
			pkt.RXChecksumValidated = d.e.caps&stack.CapabilityRXChecksumOffload != 0
			d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
		}
	}
	d.mgr.wakeReady()

	return true, nil
}
