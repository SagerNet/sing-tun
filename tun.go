package tun

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
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
	N.VectorisedWriter
	Close() error
}

type WinTun interface {
	Tun
	ReadPacket() ([]byte, func(), error)
}

type LinuxTUN interface {
	Tun
	N.FrontHeadroom
	BatchSize() int
	BatchRead(buffers [][]byte, offset int, readN []int) (n int, err error)
	BatchWrite(buffers [][]byte, offset int) error
	TXChecksumOffload() bool
}

type Options struct {
	Name                     string
	Inet4Address             []netip.Prefix
	Inet6Address             []netip.Prefix
	MTU                      uint32
	GSO                      bool
	AutoRoute                bool
	StrictRoute              bool
	Inet4RouteAddress        []netip.Prefix
	Inet6RouteAddress        []netip.Prefix
	Inet4RouteExcludeAddress []netip.Prefix
	Inet6RouteExcludeAddress []netip.Prefix
	IncludeInterface         []string
	ExcludeInterface         []string
	IncludeUID               []ranges.Range[uint32]
	ExcludeUID               []ranges.Range[uint32]
	IncludeAndroidUser       []int
	IncludePackage           []string
	ExcludePackage           []string
	InterfaceMonitor         DefaultInterfaceMonitor
	TableIndex               int
	FileDescriptor           int
	Logger                   logger.Logger

	// No work for TCP, do not use.
	_TXChecksumOffload bool
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
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
			if parseErr == nil && int(index) >= tunIndex {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}
