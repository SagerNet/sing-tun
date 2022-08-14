package tun

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ranges"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

type Tun interface {
	io.ReadWriter
	Close() error
}

type WinTun interface {
	Tun
	ReadPacket() ([]byte, func(), error)
}

type Options struct {
	Name               string
	Inet4Address       netip.Prefix
	Inet6Address       netip.Prefix
	MTU                uint32
	AutoRoute          bool
	IncludeUID         []ranges.Range[uint32]
	IncludeAndroidUser []int
	ExcludeUID         []ranges.Range[uint32]
}

func (o Options) ExcludedRanges() (uidRanges []ranges.Range[uint32]) {
	var includeAndroidUser []int
	if runtime.GOOS == "android" {
		includeAndroidUser = o.IncludeAndroidUser
	}
	return buildExcludedRanges(o.IncludeUID, o.ExcludeUID, includeAndroidUser)
}

const (
	androidUserRange        = 100000
	userEnd          uint32 = 0xFFFFFFFF - 1
)

func buildExcludedRanges(includeRanges []ranges.Range[uint32], excludeRanges []ranges.Range[uint32], includeAndroidUser []int) (uidRanges []ranges.Range[uint32]) {
	if len(includeRanges) > 0 {
		uidRanges = includeRanges
	}
	if len(includeAndroidUser) > 0 {
		includeAndroidUser = common.Uniq(includeAndroidUser)
		sort.Ints(includeAndroidUser)
		for _, androidUser := range includeAndroidUser {
			uidRanges = append(uidRanges, ranges.New[uint32](uint32(androidUser)*androidUserRange, uint32(androidUser+1)*androidUserRange-1))
		}
	}
	if len(uidRanges) > 0 {
		uidRanges = ranges.Exclude(uidRanges, excludeRanges)
		uidRanges = ranges.Revert(0, userEnd, uidRanges)
	} else {
		uidRanges = excludeRanges
	}
	return ranges.Merge(uidRanges)
}

func DefaultInterfaceName() (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}
