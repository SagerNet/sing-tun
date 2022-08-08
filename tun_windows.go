package tun

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	"github.com/sagernet/sing-tun/internal/wintun"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

var TunnelType = "sing-tun"

type NativeTun struct {
	adapter      *wintun.Adapter
	inet4Address netip.Prefix
	inet6Address netip.Prefix
	mtu          uint32
	autoRoute    bool
	session      wintun.Session
	readWait     windows.Handle
	rate         rateJuggler
	running      sync.WaitGroup
	closeOnce    sync.Once
	close        int32
}

func Open(name string, inet4Address netip.Prefix, inet6Address netip.Prefix, mtu uint32, autoRoute bool) (Tun, error) {
	adapter, err := wintun.CreateAdapter(name, TunnelType, generateGUIDByDeviceName(name))
	if err != nil {
		return nil, err
	}
	nativeTun := &NativeTun{
		adapter:      adapter,
		inet4Address: inet4Address,
		inet6Address: inet6Address,
		mtu:          mtu,
		autoRoute:    autoRoute,
	}
	err = nativeTun.configure()
	if err != nil {
		adapter.Close()
		return nil, err
	}
	return nativeTun, nil
}

func (t *NativeTun) configure() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	if t.inet4Address.IsValid() {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), []netip.Prefix{t.inet4Address})
		if err != nil {
			return E.Cause(err, "set ipv4 address")
		}
	}
	if t.inet6Address.IsValid() {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), []netip.Prefix{t.inet6Address})
		if err != nil {
			return E.Cause(err, "set ipv6 address")
		}
	}
	err := luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{t.inet4Address.Addr().Next()}, nil)
	if err != nil {
		return E.Cause(err, "set ipv4 dns")
	}
	err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), []netip.Addr{t.inet6Address.Addr().Next()}, nil)
	if err != nil {
		return E.Cause(err, "set ipv6 dns")
	}
	if t.autoRoute {
		if t.inet4Address.IsValid() {
			err = luid.AddRoute(netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.IPv4Unspecified(), 0)
			if err != nil {
				return E.Cause(err, "set ipv4 route")
			}
		}
		if t.inet6Address.IsValid() {
			err = luid.AddRoute(netip.PrefixFrom(netip.IPv6Unspecified(), 0), netip.IPv6Unspecified(), 0)
			if err != nil {
				return E.Cause(err, "set ipv6 route")
			}
		}
	}
	if t.inet4Address.IsValid() {
		var inetIf *winipcfg.MibIPInterfaceRow
		inetIf, err = luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = t.mtu
		if t.autoRoute {
			inetIf.UseAutomaticMetric = false
			inetIf.Metric = 0
		}
		err = inetIf.Set()
		if err != nil {
			return E.Cause(err, "set ipv4 options")
		}
	}
	if t.inet6Address.IsValid() {
		var inet6If *winipcfg.MibIPInterfaceRow
		inet6If, err = luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}
		inet6If.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inet6If.DadTransmits = 0
		inet6If.ManagedAddressConfigurationSupported = false
		inet6If.OtherStatefulConfigurationSupported = false
		inet6If.NLMTU = t.mtu
		if t.autoRoute {
			inet6If.UseAutomaticMetric = false
			inet6If.Metric = 0
		}
		err = inet6If.Set()
		if err != nil {
			return E.Cause(err, "set ipv6 options")
		}
	}

	return nil
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	err = t.ReadFunc(func(b []byte) {
		n = copy(p, b)
	})
	return
}

func (t *NativeTun) ReadFunc(block func(b []byte)) error {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if atomic.LoadInt32(&t.close) == 1 {
		return os.ErrClosed
	}
	start := nanotime()
	shouldSpin := atomic.LoadUint64(&t.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&t.rate.nextStartTime)) <= rateMeasurementGranularity*2
	for {
		if atomic.LoadInt32(&t.close) == 1 {
			return os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			block(packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(packetSize))
			return nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return errors.New("send ring corrupt")
		}
		return fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if atomic.LoadInt32(&t.close) == 1 {
		return 0, os.ErrClosed
	}
	t.rate.update(uint64(len(p)))
	packet, err := t.session.AllocateSendPacket(len(p))
	copy(packet, p)
	if err == nil {
		t.session.SendPacket(packet)
		return len(p), nil
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("write failed: %w", err)
}

func (t *NativeTun) write(packetElementList [][]byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if atomic.LoadInt32(&t.close) == 1 {
		return 0, os.ErrClosed
	}
	var packetSize int
	for _, packetElement := range packetElementList {
		packetSize += len(packetElement)
	}
	t.rate.update(uint64(packetSize))
	packet, err := t.session.AllocateSendPacket(packetSize)
	if err == nil {
		var index int
		for _, packetElement := range packetElementList {
			index += copy(packet[index:], packetElement)
		}
		t.session.SendPacket(packet)
		return
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("write failed: %w", err)
}

func (t *NativeTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		atomic.StoreInt32(&t.close, 1)
		windows.SetEvent(t.readWait)
		t.running.Wait()
		t.session.End()
		t.adapter.Close()
	})
	return err
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

type rateJuggler struct {
	current       uint64
	nextByteCount uint64
	nextStartTime int64
	changing      int32
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := atomic.AddUint64(&rate.nextByteCount, packetLen)
	period := uint64(now - atomic.LoadInt64(&rate.nextStartTime))
	if period >= rateMeasurementGranularity {
		if !atomic.CompareAndSwapInt32(&rate.changing, 0, 1) {
			return
		}
		atomic.StoreInt64(&rate.nextStartTime, now)
		atomic.StoreUint64(&rate.current, total*uint64(time.Second/time.Nanosecond)/period)
		atomic.StoreUint64(&rate.nextByteCount, 0)
		atomic.StoreInt32(&rate.changing, 0)
	}
}

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)
