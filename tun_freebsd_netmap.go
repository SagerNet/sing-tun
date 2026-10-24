//go:build freebsd

package tun

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// netmapRX reads packets the host stack sends into the tun.
//
// Registration is NR_REG_NIC_SW, not host rings alone. FreeBSD only queues
// those packets on the host RX ring when at least one NIC TX ring is in
// netmap mode (see the host-ring note in sys/net/netmap.h). The mbuf already
// carries the 4-byte tunnel header: tunoutput prepends it before if_transmit,
// and netmap replaces if_transmit.
//
// The host TX ring is not used. netmap injects it through if_input, and an
// L3 tun leaves if_input as if_input_default, which frees the mbuf. Writes
// stay on /dev/tun, where tunwrite strips the header and calls netisr_dispatch.
type netmapRX struct {
	fd      int
	mem     []byte
	ring    netmapRing
	pending int
	mu      sync.Mutex
	closed  bool
}

func (t *NativeTun) enableNetmap(ifName string) error {
	if t.options.MTU == 0 {
		return E.New("netmap requires a tun mtu")
	}
	if len(ifName) == 0 || len(ifName) >= len(nmreqHeader{}.Name) {
		return E.New("netmap interface name is empty or too long")
	}
	fd, err := unix.Open("/dev/netmap", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return E.Cause(err, "netmap is enabled but /dev/netmap cannot be opened; load it with `kldload netmap` (or netmap_load=\"YES\" in /boot/loader.conf) and run as root")
		}
		return E.Cause(err, "open /dev/netmap")
	}
	rx, err := registerNetmap(fd, ifName, t.options.MTU)
	if err != nil {
		return err
	}
	t.netmap = rx
	if t.options.Logger != nil {
		t.options.Logger.Info("netmap read path enabled on ", ifName, ": host RX ring, buffer ", rx.ring.bufBytes(), " bytes")
	}
	return nil
}

func registerNetmap(fd int, ifName string, mtu uint32) (*netmapRX, error) {
	// On every failure the fd is closed here. The caller must not close it again.
	ok := false
	defer func() {
		if !ok {
			_ = unix.Close(fd)
		}
	}()
	var reg nmreqRegister
	reg.Mode = nrRegNICSW
	reg.Flags = nrExclusive
	var hdr nmreqHeader
	hdr.Version = netmapAPI
	hdr.ReqType = netmapReqRegister
	copy(hdr.Name[:], ifName)
	hdr.Body = uint64(uintptr(unsafe.Pointer(&reg)))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(niocCtrl), uintptr(unsafe.Pointer(&hdr)))
	runtime.KeepAlive(&hdr)
	runtime.KeepAlive(&reg)
	if errno != 0 {
		return nil, netmapRegisterError(ifName, mtu, errno)
	}
	if reg.Memsize == 0 || reg.Memsize > uint64(^uint(0)>>1) {
		return nil, E.New("netmap register ", ifName, " returned memory size ", reg.Memsize)
	}
	if reg.HostRxRings == 0 {
		return nil, E.New("netmap register ", ifName, " did not expose a host RX ring")
	}
	mem, err := unix.Mmap(fd, 0, int(reg.Memsize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, E.Cause(err, "mmap netmap")
	}
	ring, err := netmapHostRX(mem, reg.Offset)
	if err != nil {
		_ = unix.Munmap(mem)
		return nil, E.Cause(err, "netmap host RX ring on ", ifName)
	}
	need := mtu + PacketOffset
	if ring.bufBytes() < need {
		_ = unix.Munmap(mem)
		return nil, E.New("netmap buffer is ", ring.bufBytes(), " bytes but tun mtu ", mtu, " needs ", need, " (mtu plus the 4-byte tunnel header); set `sysctl dev.netmap.buf_size=", need, "` before opening a netmap port, or lower the tun mtu. mtu 1500 fits the default 2048-byte buffer. The generic adapter also rejects an mtu above 32768")
	}
	rx := &netmapRX{fd: fd, mem: mem, ring: ring}
	// Publish the initial tail. NIOCRXSYNC does not block.
	if err = rx.sync(); err != nil {
		_ = unix.Munmap(mem)
		return nil, err
	}
	ok = true
	return rx, nil
}

func netmapRegisterError(ifName string, mtu uint32, errno syscall.Errno) error {
	hint := fmt.Sprintf("tun mtu is %d. dev.netmap.buf_size (default 2048) must be at least %d, and the mtu must be at most 32768: the generic netmap adapter cannot split a frame across buffers. Run `sysctl dev.netmap.buf_size=%d` before any netmap port is open. An mtu of 1500 works with the default buffer", mtu, mtu+PacketOffset, mtu+PacketOffset)
	switch errno {
	case unix.EINVAL, unix.ENXIO, unix.ENODEV, unix.EBUSY, unix.ENOMEM, unix.EOPNOTSUPP:
		return E.New("netmap register ", ifName, ": ", errno.Error(), "; ", hint)
	default:
		return E.New("netmap register ", ifName, ": ", errno.Error())
	}
}

func (r *netmapRX) read(p []byte) (int, error) {
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return 0, os.ErrClosed
		}
		if !r.ring.empty() {
			n, err := r.ring.copyOut(p)
			if err != nil {
				r.mu.Unlock()
				return 0, err
			}
			r.pending++
			var syncErr error
			if r.pending >= netmapReleaseEvery {
				syncErr = r.sync()
				r.pending = 0
			}
			r.mu.Unlock()
			if syncErr != nil {
				return 0, syncErr
			}
			// A runt cannot be a tun frame. Drop it and keep the ring moving.
			if n < PacketOffset {
				continue
			}
			return n, nil
		}
		r.pending = 0
		r.mu.Unlock()
		if err := r.wait(); err != nil {
			return 0, err
		}
	}
}

func (r *netmapRX) sync() error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(r.fd), uintptr(niocRxSync), 0)
	if errno != 0 {
		return os.NewSyscallError("NIOCRXSYNC", errno)
	}
	return nil
}

func (r *netmapRX) wait() error {
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return os.ErrClosed
		}
		fd := r.fd
		r.mu.Unlock()
		fds := []unix.PollFd{{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}}
		_, err := unix.Poll(fds, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if r.isClosed() || errors.Is(err, unix.EBADF) {
				return os.ErrClosed
			}
			return err
		}
		revents := fds[0].Revents
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			if r.isClosed() {
				return os.ErrClosed
			}
			return E.New("netmap poll: revents ", revents)
		}
		return nil
	}
}

func (r *netmapRX) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *netmapRX) close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	fd := r.fd
	r.fd = -1
	r.mu.Unlock()
	// Closing the fd wakes poll. Unmap only after readers have left the ring.
	var err error
	if fd >= 0 {
		err = unix.Close(fd)
	}
	r.mu.Lock()
	if r.mem != nil {
		if uerr := unix.Munmap(r.mem); err == nil {
			err = uerr
		}
		r.mem = nil
	}
	r.mu.Unlock()
	return err
}
