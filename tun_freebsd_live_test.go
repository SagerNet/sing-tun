//go:build freebsd

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Live tests install routes only for 240.0.0.0/12 in FIB 2021 and, for the
// lookup probe, the same prefixes in FIB 0 via the real gateway. The tun
// benchmark uses tun90 and 203.0.113.0/24. Neither calls prepareFIB, so the
// production proxy FIB is left alone. They do nothing unless run as root
// with FREEBSD_LIVE_TEST=1.

func TestLiveCleanup(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("FREEBSD_LIVE_CLEANUP") != "1" {
		t.Skip("set FREEBSD_LIVE_CLEANUP=1 and run as root")
	}
	gateway4, _, _, err := findDefaultGateways()
	if err != nil {
		t.Fatal(err)
	}
	prefixes := docPrefixes(4096)
	clearDocRoutesIfPresent(t, 2021, prefixes, gateway4)
	clearDocRoutesIfPresent(t, unix.RT_DEFAULT_FIB, prefixes, gateway4)
	_ = destroyTun("tun90")
	_ = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_DELETE, netip.MustParsePrefix("203.0.113.0/24"), netip.MustParseAddr("172.31.200.1"), 0)
}

func TestLiveRouteScale(t *testing.T) {
	requireLive(t)
	fibs, err := sysctlReadUint32("net.fibs")
	if err != nil {
		t.Fatal(err)
	}
	const spareFIB = 2021
	if fibs <= spareFIB {
		t.Fatalf("net.fibs=%d, need > %d", fibs, spareFIB)
	}
	gateway4, _, _, err := findDefaultGateways()
	if err != nil {
		t.Fatal(err)
	}
	if !gateway4.IsValid() {
		t.Fatal("no IPv4 default gateway")
	}
	before := routeSnapshot(t, "1.1.1.1")
	lookupBefore := timeRouteGets(200)
	ribBefore, ribErr := timeRIBLookup(unix.RT_DEFAULT_FIB, netip.MustParseAddr("1.1.1.1"), 20000)
	t.Logf("host go=%s os=%s ncpu=%s net.fibs=%d gateway=%s route_1.1.1.1=%s lookup_200=%s rib_20k=%s rib_err=%v ru_maxrss=%d",
		runtime.Version(), sysctlText("kern.osrelease"), sysctlText("hw.ncpu"), fibs, gateway4, before.iface, lookupBefore, ribBefore, ribErr, maxRSS())

	prefixes := docPrefixes(4096)
	measureRouteFIB(t, spareFIB, prefixes, gateway4)
	afterSpare := routeSnapshot(t, "1.1.1.1")
	if afterSpare.iface != before.iface {
		t.Fatalf("FIB %d install changed 1.1.1.1 from %s to %s", spareFIB, before.iface, afterSpare.iface)
	}
	measureRouteFIB(t, unix.RT_DEFAULT_FIB, prefixes, gateway4)
	after := routeSnapshot(t, "1.1.1.1")
	if after.iface != before.iface {
		t.Fatalf("FIB 0 install changed 1.1.1.1 from %s to %s", before.iface, after.iface)
	}
	if routeIs24(t, unix.RT_DEFAULT_FIB, "240.0.0.1", "240.0.0.0") {
		t.Fatal("240.0.0.0/24 still present in FIB 0 after cleanup")
	}
}

func TestLiveTunIO(t *testing.T) {
	requireLive(t)
	before := routeSnapshot(t, "1.1.1.1")
	t.Logf("netmap buf_size=%s ringsize=%s rings=%s buf_curr=%s",
		sysctlText("dev.netmap.buf_size"),
		sysctlText("dev.netmap.generic_ringsize"),
		sysctlText("dev.netmap.generic_rings"),
		sysctlText("dev.netmap.buf_curr_size"))
	secs := benchSeconds()
	for _, mode := range []struct {
		name   string
		netmap bool
		write  bool
		vector bool
		ping   bool
	}{
		{name: "read plain", netmap: false},
		{name: "read netmap", netmap: true},
		{name: "write plain", write: true},
		{name: "write netmap", write: true, netmap: true},
		{name: "write vectorised", write: true, vector: true},
		{name: "ping plain", ping: true},
		{name: "ping netmap", netmap: true, ping: true},
	} {
		if only := os.Getenv("FREEBSD_BENCH_ONLY"); only != "" && mode.name != only {
			continue
		}
		if mode.netmap {
			if _, err := os.Stat("/dev/netmap"); err != nil {
				t.Logf("BENCH %s skipped: %v", mode.name, err)
				continue
			}
		}
		var rounds []benchRound
		for round := 1; round <= benchRounds(); round++ {
			nt, err := openBenchTun(t, mode.netmap)
			if err != nil {
				if mode.netmap && strings.Contains(err.Error(), "netmap") {
					t.Logf("BENCH %s skipped: %v", mode.name, err)
					rounds = nil
					break
				}
				t.Fatal(err)
			}
			var result benchRound
			if mode.ping {
				result, err = benchPing(nt, 100)
			} else if mode.write {
				result, err = benchWrite(nt, secs, mode.vector)
			} else {
				result, err = benchRead(nt, secs)
			}
			_ = nt.Close()
			if err != nil {
				t.Fatalf("%s round %d: %v", mode.name, round, err)
			}
			rounds = append(rounds, result)
			t.Logf("BENCH %s round %d %s", mode.name, round, result.String())
		}
		if len(rounds) > 0 {
			t.Logf("BENCH %s %s", mode.name, summarizeRounds(rounds))
		}
	}
	_ = destroyTun("tun90")
	after := routeSnapshot(t, "1.1.1.1")
	if after.iface != before.iface {
		t.Fatalf("benchmark changed 1.1.1.1 from %s to %s", before.iface, after.iface)
	}
	if routeIs24(t, unix.RT_DEFAULT_FIB, "203.0.113.1", "203.0.113.0") {
		t.Fatal("203.0.113.0/24 still installed")
	}
}

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 || os.Getenv("FREEBSD_LIVE_TEST") != "1" {
		t.Skip("set FREEBSD_LIVE_TEST=1 and run as root")
	}
}

func benchSeconds() time.Duration {
	if text := os.Getenv("FREEBSD_BENCH_SECS"); text != "" {
		if n, err := strconv.Atoi(text); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Second
}

func benchRounds() int {
	if text := os.Getenv("FREEBSD_BENCH_ROUNDS"); text != "" {
		if n, err := strconv.Atoi(text); err == nil && n > 0 {
			return n
		}
	}
	return 3
}

func measureRouteFIB(t *testing.T, fib int, prefixes []netip.Prefix, gateway netip.Addr) {
	t.Helper()
	clearDocRoutesIfPresent(t, fib, prefixes, gateway)
	t.Cleanup(func() {
		clearDocRoutesIfPresent(t, fib, prefixes, gateway)
	})
	var added int
	add := func(prefix netip.Prefix) error {
		err := execRoute(fib, unix.RTM_ADD, prefix, gateway, 0)
		if err == nil {
			added++
			if added%1024 == 0 {
				t.Logf("fib %d added %d", fib, added)
			}
		}
		return err
	}
	remove := func(prefix netip.Prefix) error {
		return execRoute(fib, unix.RTM_DELETE, prefix, gateway, 0)
	}
	rssBefore := maxRSS()
	start := time.Now()
	if err := installRoutePrefixes(prefixes, add, remove); err != nil {
		t.Fatal(err)
	}
	installDur := time.Since(start)
	if !routeIs24(t, fib, "240.0.0.1", "240.0.0.0") || !routeIs24(t, fib, "240.15.255.1", "240.15.255.0") {
		out, _ := routeGet(fib, "240.0.0.1")
		t.Fatalf("fib %d missing doc prefix:\n%s", fib, out)
	}
	if fib != unix.RT_DEFAULT_FIB && routeIs24(t, unix.RT_DEFAULT_FIB, "240.0.0.1", "240.0.0.0") {
		t.Fatal("spare FIB install leaked 240.0.0.0/24 into FIB 0")
	}
	lookup := timeRouteGets(200)
	ribProbe := netip.MustParseAddr("1.1.1.1")
	ribDur, ribErr := timeRIBLookup(fib, ribProbe, 20000)
	docDur, docErr := timeRIBLookup(fib, netip.MustParseAddr("240.0.0.1"), 20000)
	t.Logf("ROUTE fib=%d rib_20k_1.1.1.1=%s err=%v rib_20k_240=%s err=%v", fib, ribDur, ribErr, docDur, docErr)
	added = 0
	start = time.Now()
	if err := installRoutePrefixes(prefixes, add, remove); err != nil {
		t.Fatal(err)
	}
	reinstallDur := time.Since(start)
	start = time.Now()
	for i := len(prefixes) - 1; i >= 0; i-- {
		if err := remove(prefixes[i]); err != nil {
			t.Fatalf("delete %s: %v", prefixes[i], err)
		}
	}
	deleteDur := time.Since(start)
	if routeIs24(t, fib, "240.0.0.1", "240.0.0.0") || routeIs24(t, fib, "240.15.255.1", "240.15.255.0") {
		t.Fatalf("fib %d still has a doc prefix after delete", fib)
	}
	t.Logf("ROUTE fib=%d prefixes=%d install=%s reinstall=%s delete=%s lookup_200_while_installed=%s ru_maxrss_before=%d ru_maxrss_after=%d",
		fib, len(prefixes), installDur, reinstallDur, deleteDur, lookup, rssBefore, maxRSS())
}

func clearDocRoutesIfPresent(t *testing.T, fib int, prefixes []netip.Prefix, gateway netip.Addr) {
	t.Helper()
	if !routeIs24(t, fib, "240.0.0.1", "240.0.0.0") && !routeIs24(t, fib, "240.8.0.1", "240.8.0.0") && !routeIs24(t, fib, "240.15.255.1", "240.15.255.0") {
		return
	}
	for i := len(prefixes) - 1; i >= 0; i-- {
		_ = execRoute(fib, unix.RTM_DELETE, prefixes[i], gateway, 0)
	}
}

func docPrefixes(n int) []netip.Prefix {
	prefixes := make([]netip.Prefix, n)
	base := binary.BigEndian.Uint32([]byte{240, 0, 0, 0})
	for i := range prefixes {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], base+uint32(i<<8))
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4(raw), 24)
	}
	return prefixes
}

type routeSnap struct {
	iface string
}

func routeSnapshot(t *testing.T, host string) routeSnap {
	t.Helper()
	out, err := routeGet(unix.RT_DEFAULT_FIB, host)
	if err != nil {
		t.Fatalf("route get %s: %v\n%s", host, err, out)
	}
	return routeSnap{iface: routeValue(out, "interface")}
}

func routeIs24(t *testing.T, fib int, host, network string) bool {
	t.Helper()
	out, err := routeGet(fib, host)
	if err != nil {
		return false
	}
	switch strings.ToLower(routeValue(out, "mask")) {
	case "255.255.255.0", "0xffffff00":
		return routeValue(out, "destination") == network
	default:
		return false
	}
}

func routeGet(fib int, host string) (string, error) {
	var cmd *exec.Cmd
	if fib == 0 {
		cmd = exec.Command("route", "-n", "get", host)
	} else {
		cmd = exec.Command("setfib", strconv.Itoa(fib), "route", "-n", "get", host)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func routeValue(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func timeRouteGets(n int) time.Duration {
	start := time.Now()
	for range n {
		_, _ = routeGet(0, "1.1.1.1")
	}
	return time.Since(start)
}

func openBenchTun(t *testing.T, useNetmap bool) (*NativeTun, error) {
	t.Helper()
	var dev Tun
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		_ = destroyTun("tun90")
		dev, err = New(Options{
			Name:              "tun90",
			MTU:               1500,
			Inet4Address:      []netip.Prefix{netip.MustParsePrefix("172.31.200.1/30")},
			Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			Netmap:            useNetmap,
		})
		if err == nil || !errors.Is(err, unix.ENXIO) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	nt := dev.(*NativeTun)
	t.Cleanup(func() {
		_ = nt.Close()
		_ = destroyTun("tun90")
		_ = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_DELETE, netip.MustParsePrefix("203.0.113.0/24"), netip.MustParseAddr("172.31.200.1"), 0)
	})
	if err = nt.setRoutes(); err != nil {
		return nil, err
	}
	return nt, nil
}

type benchRound struct {
	sent    int
	dropped int
	pkts    int
	bytes   int
	elapsed time.Duration
	user    time.Duration
	sys     time.Duration
	busy    float64
	rtts    []time.Duration
	extra   string
}

func (r benchRound) String() string {
	pps := 0.0
	if r.elapsed > 0 {
		pps = float64(r.pkts) / r.elapsed.Seconds()
	}
	loss := 0.0
	if r.sent > r.pkts {
		loss = float64(r.sent-r.pkts) / float64(r.sent)
	}
	text := fmt.Sprintf("pkts=%d bytes=%d elapsed=%s pps=%.0f sent=%d eagain=%d loss=%.4f user=%s sys=%s busy=%.3f",
		r.pkts, r.bytes, r.elapsed, pps, r.sent, r.dropped, loss, r.user, r.sys, r.busy)
	if len(r.rtts) > 0 {
		text += " " + rttSummary(r.rtts)
	}
	if r.extra != "" {
		text += " " + r.extra
	}
	return text
}

func summarizeRounds(rounds []benchRound) string {
	pps := make([]float64, 0, len(rounds))
	for _, round := range rounds {
		if round.elapsed > 0 && len(round.rtts) == 0 {
			pps = append(pps, float64(round.pkts)/round.elapsed.Seconds())
		}
	}
	if len(pps) == 0 && len(rounds) > 0 && len(rounds[0].rtts) > 0 {
		meds := make([]float64, len(rounds))
		for i, round := range rounds {
			meds[i] = float64(percentile(round.rtts, 50))
		}
		sort.Float64s(meds)
		return fmt.Sprintf("rounds=%d median_p50=%s min_p50=%s max_p50=%s", len(rounds), time.Duration(meds[len(meds)/2]), time.Duration(meds[0]), time.Duration(meds[len(meds)-1]))
	}
	if len(pps) == 0 {
		return "no samples"
	}
	sort.Float64s(pps)
	return fmt.Sprintf("rounds=%d median_pps=%.0f min_pps=%.0f max_pps=%.0f", len(pps), pps[len(pps)/2], pps[0], pps[len(pps)-1])
}

func benchRead(nt *NativeTun, d time.Duration) (benchRound, error) {
	stop := make(chan struct{})
	var sent, dropped int
	var floodErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent, dropped, floodErr = floodUDP(stop, []byte("bench"))
	}()
	sample := beginSample()
	pkts, nbytes, elapsed, readErr := readUntilClose(nt, d, true)
	user, sys, busy := sample.done()
	close(stop)
	wg.Wait()
	if readErr != nil {
		return benchRound{}, readErr
	}
	if pkts == 0 {
		return benchRound{}, fmt.Errorf("read 0 packets (flood err %v sent %d eagain %d)", floodErr, sent, dropped)
	}
	extra := ""
	if floodErr != nil {
		extra = "flood_err=" + floodErr.Error()
	}
	return benchRound{sent: sent, dropped: dropped, pkts: pkts, bytes: nbytes, elapsed: elapsed, user: user, sys: sys, busy: busy, extra: extra}, nil
}

func benchWrite(nt *NativeTun, d time.Duration, vector bool) (benchRound, error) {
	pkt := ipv4UDP([4]byte{203, 0, 113, 10}, [4]byte{172, 31, 200, 1}, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, err := nt.Read(buf); err != nil {
				return
			}
		}
	}()
	sample := beginSample()
	start := time.Now()
	end := start.Add(d)
	var pkts, failed int
	ip := buf.As(pkt[4:])
	for time.Now().Before(end) {
		var err error
		if vector {
			err = nt.WriteVectorised([]*buf.Buffer{ip})
		} else {
			_, err = nt.Write(pkt)
		}
		if err != nil {
			failed++
			continue
		}
		pkts++
	}
	elapsed := time.Since(start)
	user, sys, busy := sample.done()
	_ = nt.Close()
	wg.Wait()
	if pkts == 0 {
		return benchRound{}, fmt.Errorf("write 0 packets, failed %d", failed)
	}
	return benchRound{pkts: pkts, bytes: pkts * len(pkt), elapsed: elapsed, user: user, sys: sys, busy: busy, extra: fmt.Sprintf("write_err=%d", failed)}, nil
}

func benchPing(nt *NativeTun, n int) (benchRound, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 9})
	if err != nil {
		return benchRound{}, err
	}
	defer conn.Close()
	payload := []byte("p")
	buffer := make([]byte, 2048)
	samples := make([]time.Duration, 0, n)
	sample := beginSample()
	for range n {
		start := time.Now()
		if _, err = conn.Write(payload); err != nil {
			return benchRound{}, err
		}
		got := make(chan error, 1)
		go func() {
			_, readErr := nt.Read(buffer)
			got <- readErr
		}()
		select {
		case readErr := <-got:
			if readErr != nil {
				return benchRound{}, readErr
			}
			samples = append(samples, time.Since(start))
		case <-time.After(time.Second):
			_ = nt.Close()
			return benchRound{}, fmt.Errorf("read timed out after %d samples", len(samples))
		}
	}
	user, sys, busy := sample.done()
	return benchRound{pkts: len(samples), elapsed: sumDurations(samples), user: user, sys: sys, busy: busy, rtts: samples}, nil
}

func readUntilClose(nt *NativeTun, d time.Duration, checkIPv4 bool) (pkts, nbytes int, elapsed time.Duration, err error) {
	buffer := make([]byte, 2048)
	start := time.Now()
	timer := time.AfterFunc(d, func() { _ = nt.Close() })
	defer timer.Stop()
	for {
		var n int
		n, err = nt.Read(buffer)
		if err != nil {
			// Close unblocks the last read. A short window with packets is success.
			if pkts > 0 {
				err = nil
			}
			return pkts, nbytes, time.Since(start), err
		}
		if checkIPv4 && pkts == 0 && (n < 5 || buffer[4]>>4 != 4) {
			_ = nt.Close()
			return 0, 0, time.Since(start), fmt.Errorf("unexpected packet len %d head %x", n, buffer[:min(n, 8)])
		}
		pkts++
		nbytes += n
	}
}

func floodUDP(stop <-chan struct{}, payload []byte) (sent, dropped int, err error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 9})
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var ctrlErr error
	if err = raw.Control(func(fd uintptr) {
		ctrlErr = unix.SetNonblock(int(fd), true)
	}); err != nil {
		return 0, 0, err
	}
	if ctrlErr != nil {
		return 0, 0, ctrlErr
	}
	for {
		select {
		case <-stop:
			return sent, dropped, nil
		default:
		}
		if _, err = conn.Write(payload); err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.ENOBUFS) {
				dropped++
				runtime.Gosched()
				continue
			}
			return sent, dropped, err
		}
		sent++
	}
}

func timeRIBLookup(fib int, addr netip.Addr, n int) (time.Duration, error) {
	// No netmask: an exact /32 lookup returns ESRCH when only a covering
	// route exists. route(8) get does a longest-match lookup the same way.
	message := route.RouteMessage{
		Type:    unix.RTM_GET,
		Version: unix.RTM_VERSION,
		Addrs: []route.Addr{
			syscall.RTAX_DST: &route.Inet4Addr{IP: addr.As4()},
		},
	}
	request, err := message.Marshal()
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SETFIB, fib); err != nil {
		return 0, err
	}
	tv := unix.Timeval{Sec: 1}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, err
	}
	reply := make([]byte, 2048)
	if _, err = unix.Write(fd, request); err != nil {
		return 0, err
	}
	if _, err = unix.Read(fd, reply); err != nil {
		return 0, err
	}
	start := time.Now()
	for range n {
		if _, err = unix.Write(fd, request); err != nil {
			return 0, err
		}
		if _, err = unix.Read(fd, reply); err != nil {
			return 0, err
		}
	}
	return time.Since(start), nil
}

func ipv4UDP(src, dst [4]byte, payloadLen int) []byte {
	total := 20 + 8 + payloadLen
	pkt := make([]byte, 4+total)
	pkt[3] = unix.AF_INET
	ip := pkt[4:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	sum := ipChecksum(ip[:20])
	binary.BigEndian.PutUint16(ip[10:], sum)
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 9)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+payloadLen))
	return pkt
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type cpuSample struct {
	rusage unix.Rusage
	cp     [5]uint64
	ok     bool
}

func beginSample() cpuSample {
	var sample cpuSample
	if err := unix.Getrusage(unix.RUSAGE_SELF, &sample.rusage); err != nil {
		return sample
	}
	sample.cp, sample.ok = readCPTime()
	return sample
}

func (s cpuSample) done() (user, sys time.Duration, busy float64) {
	var after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err == nil {
		user = timevalDuration(after.Utime) - timevalDuration(s.rusage.Utime)
		sys = timevalDuration(after.Stime) - timevalDuration(s.rusage.Stime)
	}
	if s.ok {
		if cp, ok := readCPTime(); ok {
			var total, idle uint64
			for i := range cp {
				delta := cp[i] - s.cp[i]
				total += delta
				if i == 4 {
					idle = delta
				}
			}
			if total > 0 {
				busy = float64(total-idle) / float64(total)
			}
		}
	}
	return user, sys, busy
}

func timevalDuration(tv unix.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

func readCPTime() ([5]uint64, bool) {
	var out [5]uint64
	fields := strings.Fields(sysctlText("kern.cp_time"))
	if len(fields) < 5 {
		return out, false
	}
	for i := 0; i < 5; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return out, false
		}
		out[i] = value
	}
	return out, true
}

func maxRSS() int64 {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return usage.Maxrss
}

func sysctlText(name string) string {
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func rttSummary(samples []time.Duration) string {
	return fmt.Sprintf("rtt_p50=%s rtt_p99=%s rtt_min=%s rtt_max=%s",
		percentile(samples, 50), percentile(samples, 99), percentile(samples, 0), percentile(samples, 100))
}

func percentile(samples []time.Duration, pct int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	if pct <= 0 {
		return cp[0]
	}
	if pct >= 100 {
		return cp[len(cp)-1]
	}
	idx := (len(cp) - 1) * pct / 100
	return cp[idx]
}

func sumDurations(samples []time.Duration) time.Duration {
	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	return total
}
