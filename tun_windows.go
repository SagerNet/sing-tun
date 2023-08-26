package tun

import (
	"crypto/md5"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	"github.com/sagernet/sing-tun/internal/winsys"
	"github.com/sagernet/sing-tun/internal/wintun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/windnsapi"

	"golang.org/x/sys/windows"
)

var TunnelType = "sing-tun"

type NativeTun struct {
	adapter     *wintun.Adapter
	options     Options
	session     wintun.Session
	readWait    windows.Handle
	rate        rateJuggler
	running     sync.WaitGroup
	closeOnce   sync.Once
	close       int32
	fwpmSession uintptr
}

func New(options Options) (WinTun, error) {
	if options.FileDescriptor != 0 {
		return nil, os.ErrInvalid
	}
	adapter, err := wintun.CreateAdapter(options.Name, TunnelType, generateGUIDByDeviceName(options.Name))
	if err != nil {
		return nil, err
	}
	nativeTun := &NativeTun{
		adapter: adapter,
		options: options,
	}
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		return nil, err
	}
	nativeTun.session = session
	nativeTun.readWait = session.ReadWaitEvent()
	err = nativeTun.configure()
	if err != nil {
		session.End()
		adapter.Close()
		return nil, err
	}
	return nativeTun, nil
}

func (t *NativeTun) configure() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	if len(t.options.Inet4Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), t.options.Inet4Address)
		if err != nil {
			return E.Cause(err, "set ipv4 address")
		}
		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{t.options.Inet4Address[0].Addr().Next()}, nil)
		if err != nil {
			return E.Cause(err, "set ipv4 dns")
		}
	}
	if len(t.options.Inet6Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), t.options.Inet6Address)
		if err != nil {
			return E.Cause(err, "set ipv6 address")
		}
		err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), []netip.Addr{t.options.Inet6Address[0].Addr().Next()}, nil)
		if err != nil {
			return E.Cause(err, "set ipv6 dns")
		}
	}
	if len(t.options.Inet4Address) > 0 || len(t.options.Inet6Address) > 0 {
		_ = luid.DisableDNSRegistration()
	}
	if t.options.AutoRoute {
		if len(t.options.Inet4Address) > 0 {
			if len(t.options.Inet4RouteAddress) > 0 {
				for _, addr := range t.options.Inet4RouteAddress {
					err := luid.AddRoute(addr, netip.IPv4Unspecified(), 0)
					if err != nil {
						return E.Cause(err, "add ipv4 route: ", addr)
					}
				}
			} else {
				err := luid.AddRoute(netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.IPv4Unspecified(), 0)
				if err != nil {
					return E.Cause(err, "set ipv4 route")
				}
			}
		}
		if len(t.options.Inet6Address) > 0 {
			if len(t.options.Inet6RouteAddress) > 0 {
				for _, addr := range t.options.Inet6RouteAddress {
					err := luid.AddRoute(addr, netip.IPv6Unspecified(), 0)
					if err != nil {
						return E.Cause(err, "add ipv6 route: ", addr)
					}
				}
			} else {
				err := luid.AddRoute(netip.PrefixFrom(netip.IPv6Unspecified(), 0), netip.IPv6Unspecified(), 0)
				if err != nil {
					return E.Cause(err, "set ipv6 route")
				}
			}
		}
		err := windnsapi.FlushResolverCache()
		if err != nil {
			return err
		}
	}
	if len(t.options.Inet4Address) > 0 {
		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inetIf.UseAutomaticMetric = false
			inetIf.Metric = 0
		}
		err = inetIf.Set()
		if err != nil {
			return E.Cause(err, "set ipv4 options")
		}
	}
	if len(t.options.Inet6Address) > 0 {
		inet6If, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}
		inet6If.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inet6If.DadTransmits = 0
		inet6If.ManagedAddressConfigurationSupported = false
		inet6If.OtherStatefulConfigurationSupported = false
		inet6If.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inet6If.UseAutomaticMetric = false
			inet6If.Metric = 0
		}
		err = inet6If.Set()
		if err != nil {
			return E.Cause(err, "set ipv6 options")
		}
	}

	if t.options.AutoRoute && t.options.StrictRoute {
		var engine uintptr
		session := &winsys.FWPM_SESSION0{Flags: winsys.FWPM_SESSION_FLAG_DYNAMIC}
		err := winsys.FwpmEngineOpen0(nil, winsys.RPC_C_AUTHN_DEFAULT, nil, session, unsafe.Pointer(&engine))
		if err != nil {
			return os.NewSyscallError("FwpmEngineOpen0", err)
		}
		t.fwpmSession = engine

		subLayerKey, err := windows.GenerateGUID()
		if err != nil {
			return os.NewSyscallError("CoCreateGuid", err)
		}

		subLayer := winsys.FWPM_SUBLAYER0{}
		subLayer.SubLayerKey = subLayerKey
		subLayer.DisplayData = winsys.CreateDisplayData(TunnelType, "auto-route rules")
		subLayer.Weight = math.MaxUint16
		err = winsys.FwpmSubLayerAdd0(engine, &subLayer, 0)
		if err != nil {
			return os.NewSyscallError("FwpmSubLayerAdd0", err)
		}

		processAppID, err := winsys.GetCurrentProcessAppID()
		if err != nil {
			return err
		}
		defer winsys.FwpmFreeMemory0(unsafe.Pointer(&processAppID))

		var filterId uint64
		permitCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
		permitCondition[0].FieldKey = winsys.FWPM_CONDITION_ALE_APP_ID
		permitCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
		permitCondition[0].ConditionValue.Type = winsys.FWP_BYTE_BLOB_TYPE
		permitCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(processAppID))

		permitFilter4 := winsys.FWPM_FILTER0{}
		permitFilter4.FilterCondition = &permitCondition[0]
		permitFilter4.NumFilterConditions = 1
		permitFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "protect ipv4")
		permitFilter4.SubLayerKey = subLayerKey
		permitFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		permitFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
		permitFilter4.Weight.Type = winsys.FWP_UINT8
		permitFilter4.Weight.Value = uintptr(13)
		permitFilter4.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
		err = winsys.FwpmFilterAdd0(engine, &permitFilter4, 0, &filterId)
		if err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}

		permitFilter6 := winsys.FWPM_FILTER0{}
		permitFilter6.FilterCondition = &permitCondition[0]
		permitFilter6.NumFilterConditions = 1
		permitFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "protect ipv6")
		permitFilter6.SubLayerKey = subLayerKey
		permitFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		permitFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
		permitFilter6.Weight.Type = winsys.FWP_UINT8
		permitFilter6.Weight.Value = uintptr(13)
		permitFilter6.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
		err = winsys.FwpmFilterAdd0(engine, &permitFilter6, 0, &filterId)
		if err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}

		/*if len(t.options.Inet4Address) == 0 {
			blockFilter := winsys.FWPM_FILTER0{}
			blockFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv4")
			blockFilter.SubLayerKey = subLayerKey
			blockFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
			blockFilter.Action.Type = winsys.FWP_ACTION_BLOCK
			blockFilter.Weight.Type = winsys.FWP_UINT8
			blockFilter.Weight.Value = uintptr(12)
			err = winsys.FwpmFilterAdd0(engine, &blockFilter, 0, &filterId)
			if err != nil {
				return os.NewSyscallError("FwpmFilterAdd0", err)
			}
		}*/

		if len(t.options.Inet6Address) == 0 {
			blockFilter := winsys.FWPM_FILTER0{}
			blockFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6")
			blockFilter.SubLayerKey = subLayerKey
			blockFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
			blockFilter.Action.Type = winsys.FWP_ACTION_BLOCK
			blockFilter.Weight.Type = winsys.FWP_UINT8
			blockFilter.Weight.Value = uintptr(12)
			err = winsys.FwpmFilterAdd0(engine, &blockFilter, 0, &filterId)
			if err != nil {
				return os.NewSyscallError("FwpmFilterAdd0", err)
			}
		}

		netInterface, err := net.InterfaceByName(t.options.Name)
		if err != nil {
			return err
		}

		tunCondition := make([]winsys.FWPM_FILTER_CONDITION0, 1)
		tunCondition[0].FieldKey = winsys.FWPM_CONDITION_LOCAL_INTERFACE_INDEX
		tunCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
		tunCondition[0].ConditionValue.Type = winsys.FWP_UINT32
		tunCondition[0].ConditionValue.Value = uintptr(uint32(netInterface.Index))

		if len(t.options.Inet4Address) > 0 {
			tunFilter4 := winsys.FWPM_FILTER0{}
			tunFilter4.FilterCondition = &tunCondition[0]
			tunFilter4.NumFilterConditions = 1
			tunFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv4")
			tunFilter4.SubLayerKey = subLayerKey
			tunFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
			tunFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
			tunFilter4.Weight.Type = winsys.FWP_UINT8
			tunFilter4.Weight.Value = uintptr(11)
			err = winsys.FwpmFilterAdd0(engine, &tunFilter4, 0, &filterId)
			if err != nil {
				return os.NewSyscallError("FwpmFilterAdd0", err)
			}
		}

		if len(t.options.Inet6Address) > 0 {
			tunFilter6 := winsys.FWPM_FILTER0{}
			tunFilter6.FilterCondition = &tunCondition[0]
			tunFilter6.NumFilterConditions = 1
			tunFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv6")
			tunFilter6.SubLayerKey = subLayerKey
			tunFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
			tunFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
			tunFilter6.Weight.Type = winsys.FWP_UINT8
			tunFilter6.Weight.Value = uintptr(11)
			err = winsys.FwpmFilterAdd0(engine, &tunFilter6, 0, &filterId)
			if err != nil {
				return os.NewSyscallError("FwpmFilterAdd0", err)
			}
		}

		blockDNSCondition := make([]winsys.FWPM_FILTER_CONDITION0, 2)
		blockDNSCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_PROTOCOL
		blockDNSCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
		blockDNSCondition[0].ConditionValue.Type = winsys.FWP_UINT8
		blockDNSCondition[0].ConditionValue.Value = uintptr(uint8(winsys.IPPROTO_UDP))
		blockDNSCondition[1].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_PORT
		blockDNSCondition[1].MatchType = winsys.FWP_MATCH_EQUAL
		blockDNSCondition[1].ConditionValue.Type = winsys.FWP_UINT16
		blockDNSCondition[1].ConditionValue.Value = uintptr(uint16(53))

		blockDNSFilter4 := winsys.FWPM_FILTER0{}
		blockDNSFilter4.FilterCondition = &blockDNSCondition[0]
		blockDNSFilter4.NumFilterConditions = 2
		blockDNSFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv4 dns")
		blockDNSFilter4.SubLayerKey = subLayerKey
		blockDNSFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		blockDNSFilter4.Action.Type = winsys.FWP_ACTION_BLOCK
		blockDNSFilter4.Weight.Type = winsys.FWP_UINT8
		blockDNSFilter4.Weight.Value = uintptr(10)
		err = winsys.FwpmFilterAdd0(engine, &blockDNSFilter4, 0, &filterId)
		if err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}

		blockDNSFilter6 := winsys.FWPM_FILTER0{}
		blockDNSFilter6.FilterCondition = &blockDNSCondition[0]
		blockDNSFilter6.NumFilterConditions = 2
		blockDNSFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6 dns")
		blockDNSFilter6.SubLayerKey = subLayerKey
		blockDNSFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		blockDNSFilter6.Action.Type = winsys.FWP_ACTION_BLOCK
		blockDNSFilter6.Weight.Type = winsys.FWP_UINT8
		blockDNSFilter6.Weight.Value = uintptr(10)
		err = winsys.FwpmFilterAdd0(engine, &blockDNSFilter6, 0, &filterId)
		if err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}
	}

	return nil
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	return 0, os.ErrInvalid
}

func (t *NativeTun) ReadPacket() ([]byte, func(), error) {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if atomic.LoadInt32(&t.close) == 1 {
		return nil, nil, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := atomic.LoadUint64(&t.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&t.rate.nextStartTime)) <= rateMeasurementGranularity*2
	for {
		if atomic.LoadInt32(&t.close) == 1 {
			return nil, nil, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			t.rate.update(uint64(packetSize))
			return packet, func() { t.session.ReleaseReceivePacket(packet) }, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(t.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return nil, nil, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return nil, nil, errors.New("send ring corrupt")
		}
		return nil, nil, fmt.Errorf("read failed: %w", err)
	}
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

func (t *NativeTun) CreateVectorisedWriter() N.VectorisedWriter {
	return t
}

func (t *NativeTun) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	return common.Error(t.write(buf.ToSliceMulti(buffers)))
}

func (t *NativeTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		atomic.StoreInt32(&t.close, 1)
		windows.SetEvent(t.readWait)
		t.running.Wait()
		t.session.End()
		t.adapter.Close()
		if t.fwpmSession != 0 {
			winsys.FwpmEngineClose0(t.fwpmSession)
		}
		if t.options.AutoRoute {
			windnsapi.FlushResolverCache()
		}
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
