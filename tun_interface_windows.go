package tun

import (
	"net/netip"
	"slices"
	"strconv"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

type interfaceFamily struct {
	luid   winipcfg.LUID
	family winipcfg.AddressFamily
}

func routeFamilies(routeRanges []netip.Prefix) []winipcfg.AddressFamily {
	var families []winipcfg.AddressFamily
	if slices.ContainsFunc(routeRanges, func(it netip.Prefix) bool { return it.Addr().Is4() }) {
		families = append(families, windows.AF_INET)
	}
	if slices.ContainsFunc(routeRanges, func(it netip.Prefix) bool { return it.Addr().Is6() }) {
		families = append(families, windows.AF_INET6)
	}
	return families
}

func (t *NativeTun) enforceInterfaceOptions(tunInterface winipcfg.LUID) {
	t.interfaceAccess.Lock()
	defer t.interfaceAccess.Unlock()
	if t.close.Load() == 1 {
		return
	}
	defaultInterface := t.options.InterfaceMonitor.DefaultInterface()
	for _, family := range t.routeFamilies {
		rows, err := winipcfg.GetIPInterfaceTable(family)
		if err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Error(E.Cause(err, "list ", addressFamilyName(family), " interfaces"))
			}
			continue
		}
		for _, row := range rows {
			// A RAS connection that uses the default gateway on the remote network sets DisableDefaultRoutes on
			// every other interface, including ones created after it, and redialing it resets their metric to
			// automatic.
			if row.InterfaceLUID == tunInterface {
				if !row.DisableDefaultRoutes && !row.UseAutomaticMetric && row.Metric == 0 {
					continue
				}
				var tunRow winipcfg.MibIPInterfaceRow
				tunRow.Init()
				tunRow.Family = family
				tunRow.InterfaceLUID = tunInterface
				tunRow.DisableDefaultRoutes = false
				tunRow.UseAutomaticMetric = false
				tunRow.Metric = 0
				err = tunRow.Set()
				if err != nil {
					if t.options.Logger != nil {
						t.options.Logger.Error(E.Cause(err, "restore ", addressFamilyName(family), " default route options of TUN"))
					}
				} else if t.options.Logger != nil {
					t.options.Logger.Info("restored ", addressFamilyName(family), " default route options of TUN (disable default routes: ",
						row.DisableDefaultRoutes, ", automatic metric: ", row.UseAutomaticMetric, ", metric: ", row.Metric, ")")
				}
				continue
			}
			// tcpip.sys ignores IP_UNICAST_IF and IPV6_UNICAST_IF for unicast destinations when the bound
			// interface has forwarding or weak host send enabled for that family. Teredo enables IPv6 weak host
			// send on every interface when it qualifies as a host-specific relay. Weak host send changes raise no
			// interface change notification, but Teredo enables weak host receive on its own interface right
			// after, which does.
			key := interfaceFamily{luid: row.InterfaceLUID, family: family}
			if row.ForwardingEnabled && defaultInterface != nil && row.InterfaceIndex == uint32(defaultInterface.Index) && !slices.Contains(t.forwardingWarned, key) {
				t.forwardingWarned = append(t.forwardingWarned, key)
				if t.options.Logger != nil {
					t.options.Logger.Warn(addressFamilyName(family), " forwarding is enabled on ", defaultInterface.Name,
						", which makes Windows ignore interface binding and route outbound connections back into the TUN; ",
						"if it is enabled by Mobile Hotspot or Internet Connection Sharing, share the TUN interface instead")
				}
			}
			if !row.WeakHostSend {
				continue
			}
			interfaceName := strconv.FormatUint(uint64(row.InterfaceIndex), 10)
			var interfaceRow *winipcfg.MibIfRow2
			interfaceRow, err = row.InterfaceLUID.Interface()
			if err == nil {
				interfaceName = interfaceRow.Alias()
			}
			err = setWeakHostSend(row.InterfaceLUID, family, false)
			if err != nil {
				if t.options.Logger != nil {
					t.options.Logger.Error(E.Cause(err, "disable ", addressFamilyName(family), " weak host send on ", interfaceName))
				}
				continue
			}
			_, loaded := t.weakHostSendDisabled[key]
			if !loaded {
				t.weakHostSendDisabled[key] = interfaceName
				if t.options.Logger != nil {
					t.options.Logger.Info("disabled ", addressFamilyName(family), " weak host send on ", interfaceName,
						" while the TUN is running, as it makes Windows ignore interface binding")
				}
			}
		}
	}
}

func (t *NativeTun) restoreWeakHostSend() {
	t.interfaceAccess.Lock()
	defer t.interfaceAccess.Unlock()
	for disabled, name := range t.weakHostSendDisabled {
		_, err := disabled.luid.IPInterface(disabled.family)
		if err != nil {
			continue
		}
		err = setWeakHostSend(disabled.luid, disabled.family, true)
		if err != nil && t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "restore ", addressFamilyName(disabled.family), " weak host send on ", name))
		}
	}
}

// InitializeIpInterfaceEntry fills exactly the values that SetIpInterfaceEntry skips.
func setWeakHostSend(luid winipcfg.LUID, family winipcfg.AddressFamily, enabled bool) error {
	var row winipcfg.MibIPInterfaceRow
	row.Init()
	row.Family = family
	row.InterfaceLUID = luid
	row.WeakHostSend = enabled
	return row.Set()
}

func addressFamilyName(family winipcfg.AddressFamily) string {
	if family == windows.AF_INET {
		return "IPv4"
	}
	return "IPv6"
}
