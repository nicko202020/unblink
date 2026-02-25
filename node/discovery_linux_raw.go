//go:build linux

package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"

	"net"

	"golang.org/x/sys/unix"
)

type linuxScanTarget struct {
	iface  net.Interface
	srcIP  netip.Addr
	prefix netip.Prefix
	hosts  []netip.Addr
}

func discoverOpenPorts(ctx context.Context, opts DiscoveryOptions, candidates []uint16) (*openPortScanResult, error) {
	targets, networks, interfaces, hostCandidates, err := linuxTargets(opts.InterfaceWhitelist)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return &openPortScanResult{
			Networks:       networks,
			Interfaces:     interfaces,
			HostCandidates: hostCandidates,
			Hosts:          map[netip.Addr]*scanHost{},
			OpenPorts:      map[netip.Addr]map[uint16]bool{},
			StageMs:        map[string]int64{},
		}, nil
	}

	hosts := make(map[netip.Addr]*scanHost, 256)
	openPorts := make(map[netip.Addr]map[uint16]bool, 256)
	stageDurations := map[string]int64{
		"arp_scan":     0,
		"icmp_scan":    0,
		"tcp_syn_scan": 0,
	}

	arpStart := time.Now()
	for _, target := range targets {
		hits, err := arpScanInterface(ctx, target, opts.RequestTimeout)
		if err != nil {
			return nil, enrichPermissionError(fmt.Errorf("arp scan on %s: %w", target.iface.Name, err))
		}
		for ip, mac := range hits {
			host := ensureHost(hosts, ip)
			wasARP := host.ARP
			host.ARP = true
			if len(mac) > 0 {
				host.MAC = cloneMAC(mac)
			}
			if !wasARP {
				log.Printf("[Discovery][HIT] arp ip=%s mac=%s iface=%s", ip, formatMAC(host.MAC), target.iface.Name)
			}
		}
	}
	stageDurations["arp_scan"] = time.Since(arpStart).Milliseconds()

	icmpStart := time.Now()
	for _, target := range targets {
		hits, err := icmpScanInterface(ctx, target, opts.RequestTimeout)
		if err != nil {
			return nil, enrichPermissionError(fmt.Errorf("icmp scan on %s: %w", target.iface.Name, err))
		}
		for ip, mac := range hits {
			host := ensureHost(hosts, ip)
			wasICMP := host.ICMP
			host.ICMP = true
			if len(mac) > 0 {
				host.MAC = cloneMAC(mac)
			}
			if !wasICMP {
				log.Printf("[Discovery][HIT] icmp ip=%s mac=%s iface=%s", ip, formatMAC(host.MAC), target.iface.Name)
			}
		}
	}
	stageDurations["icmp_scan"] = time.Since(icmpStart).Milliseconds()

	tcpProbes := 0
	tcpStart := time.Now()
	for _, target := range targets {
		targetHosts := hostsForPrefix(hosts, target.prefix)
		if len(targetHosts) == 0 {
			continue
		}
		hits, probes, err := tcpSynScanInterface(ctx, target, targetHosts, candidates, opts.RequestTimeout)
		if err != nil {
			return nil, enrichPermissionError(fmt.Errorf("tcp syn scan on %s: %w", target.iface.Name, err))
		}
		tcpProbes += probes
		for ip, ports := range hits {
			dst := openPorts[ip]
			if dst == nil {
				dst = make(map[uint16]bool, len(ports))
				openPorts[ip] = dst
			}
			for port := range ports {
				if !dst[port] {
					dst[port] = true
					mac := ""
					if host := hosts[ip]; host != nil {
						mac = formatMAC(host.MAC)
					}
					log.Printf("[Discovery][HIT] tcp ip=%s mac=%s port=%d iface=%s", ip, mac, port, target.iface.Name)
				}
			}
		}
	}
	stageDurations["tcp_syn_scan"] = time.Since(tcpStart).Milliseconds()

	arpHosts := 0
	icmpHosts := 0
	for _, host := range hosts {
		if host.ARP {
			arpHosts++
		}
		if host.ICMP {
			icmpHosts++
		}
	}

	return &openPortScanResult{
		Networks:       networks,
		Interfaces:     interfaces,
		HostCandidates: hostCandidates,
		Hosts:          hosts,
		OpenPorts:      openPorts,
		ARPHosts:       arpHosts,
		ICMPHosts:      icmpHosts,
		TCPProbes:      tcpProbes,
		StageMs:        stageDurations,
	}, nil
}

func linuxTargets(whitelist []string) ([]linuxScanTarget, []string, []string, int, error) {
	allowed := make(map[string]bool, len(whitelist))
	for _, name := range whitelist {
		name = strings.TrimSpace(name)
		if name != "" {
			allowed[name] = true
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("list interfaces: %w", err)
	}

	targets := make([]linuxScanTarget, 0, 8)
	networks := make([]string, 0, 8)
	interfaces := make([]string, 0, 8)
	hostCandidates := 0

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(allowed) > 0 && !allowed[iface.Name] {
			continue
		}
		if len(iface.HardwareAddr) < 6 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.Mask == nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP.To4())
			if !ok || !ip.Is4() {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones <= 0 || ones > 30 {
				continue
			}

			prefix := netip.PrefixFrom(ip, ones).Masked()
			hosts := hostsInPrefix(prefix, ip)
			if len(hosts) == 0 {
				continue
			}

			targets = append(targets, linuxScanTarget{
				iface:  iface,
				srcIP:  ip,
				prefix: prefix,
				hosts:  hosts,
			})
			networks = append(networks, prefix.String())
			interfaces = append(interfaces, iface.Name)
			hostCandidates += len(hosts)
		}
	}

	sort.Strings(networks)
	networks = uniqueStrings(networks)
	sort.Strings(interfaces)
	interfaces = uniqueStrings(interfaces)

	return targets, networks, interfaces, hostCandidates, nil
}

func hostsInPrefix(prefix netip.Prefix, self netip.Addr) []netip.Addr {
	ones := prefix.Bits()
	size := 1 << (32 - ones)
	if size <= 2 {
		return nil
	}
	networkAddr := prefix.Addr()
	broadcast := addToIPv4(networkAddr, uint32(size-1))

	out := make([]netip.Addr, 0, size-2)
	cur := addToIPv4(networkAddr, 1)
	for cur != broadcast {
		if cur != self {
			out = append(out, cur)
		}
		cur = addToIPv4(cur, 1)
	}
	return out
}

func ensureHost(hosts map[netip.Addr]*scanHost, ip netip.Addr) *scanHost {
	host := hosts[ip]
	if host == nil {
		host = &scanHost{IP: ip}
		hosts[ip] = host
	}
	return host
}

func hostsForPrefix(hosts map[netip.Addr]*scanHost, prefix netip.Prefix) map[netip.Addr]*scanHost {
	out := make(map[netip.Addr]*scanHost, len(hosts))
	for ip, host := range hosts {
		if prefix.Contains(ip) {
			out[ip] = host
		}
	}
	return out
}

func cloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 0 {
		return nil
	}
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

func arpScanInterface(ctx context.Context, target linuxScanTarget, timeout time.Duration) (map[netip.Addr]net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  target.iface.Index,
	}); err != nil {
		return nil, err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 80 * 1000})

	dst := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  target.iface.Index,
		Halen:    6,
		Addr:     [8]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	srcIP := target.srcIP.As4()
	targetSet := make(map[netip.Addr]bool, len(target.hosts))
	for _, ip := range target.hosts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		targetSet[ip] = true
		frame := buildARPRequest(target.iface.HardwareAddr[:6], srcIP, ip.As4())
		if err := unix.Sendto(fd, frame, 0, dst); err != nil {
			return nil, err
		}
	}

	hits := make(map[netip.Addr]net.HardwareAddr, 64)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return hits, nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if n < 42 {
			continue
		}
		frame := buf[:n]
		if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
			continue
		}
		arp := frame[14:]
		if len(arp) < 28 || binary.BigEndian.Uint16(arp[6:8]) != 2 {
			continue
		}
		if !bytes.Equal(arp[24:28], srcIP[:]) {
			continue
		}
		ip, ok := netip.AddrFromSlice(arp[14:18])
		if !ok || !ip.Is4() || !targetSet[ip] {
			continue
		}
		hits[ip] = cloneMAC(net.HardwareAddr(arp[8:14]))
	}
	return hits, nil
}

func icmpScanInterface(ctx context.Context, target linuxScanTarget, timeout time.Duration) (map[netip.Addr]net.HardwareAddr, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  target.iface.Index,
	}); err != nil {
		return nil, err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 80 * 1000})

	dst := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  target.iface.Index,
		Halen:    6,
		Addr:     [8]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	hostSet := make(map[netip.Addr]bool, len(target.hosts))
	for _, ip := range target.hosts {
		hostSet[ip] = true
	}

	for _, ip := range target.hosts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		id, seq := idSeqFromIPv4(ip)
		frame := buildICMPEchoFrame(target.iface.HardwareAddr[:6], target.srcIP.As4(), ip.As4(), id, seq)
		if err := unix.Sendto(fd, frame, 0, dst); err != nil {
			return nil, err
		}
	}

	hits := make(map[netip.Addr]net.HardwareAddr, 64)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return hits, nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return nil, err
		}
		if n < 42 {
			continue
		}
		frame := buf[:n]
		if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
			continue
		}
		ipHeader := frame[14:]
		ihl := int((ipHeader[0] & 0x0f) * 4)
		if ihl < 20 || len(ipHeader) < ihl+8 {
			continue
		}
		if ipHeader[9] != 1 {
			continue
		}
		if !bytes.Equal(ipHeader[16:20], target.srcIP.AsSlice()) {
			continue
		}
		icmp := ipHeader[ihl:]
		if len(icmp) < 8 || icmp[0] != 0 {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipHeader[12:16])
		if !ok || !ip.Is4() || !hostSet[ip] {
			continue
		}
		hits[ip] = cloneMAC(net.HardwareAddr(frame[6:12]))
	}
	return hits, nil
}

func tcpSynScanInterface(ctx context.Context, target linuxScanTarget, hosts map[netip.Addr]*scanHost, candidates []uint16, timeout time.Duration) (map[netip.Addr]map[uint16]bool, int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, 0, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  target.iface.Index,
	}); err != nil {
		return nil, 0, err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 80 * 1000})

	const srcPort = uint16(61234)
	seq := uint32(time.Now().UnixNano())
	probes := 0
	for ip, host := range hosts {
		if len(host.MAC) < 6 {
			continue
		}
		dst := &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_IP),
			Ifindex:  target.iface.Index,
			Halen:    6,
		}
		copy(dst.Addr[:], host.MAC[:6])
		for _, dstPort := range candidates {
			select {
			case <-ctx.Done():
				return nil, probes, ctx.Err()
			default:
			}
			packet := buildTCPSYNFrame(target.iface.HardwareAddr[:6], host.MAC[:6], target.srcIP.As4(), ip.As4(), srcPort, dstPort, seq)
			seq++
			if err := unix.Sendto(fd, packet, 0, dst); err != nil {
				return nil, probes, err
			}
			probes++
		}
	}

	candidateSet := make(map[uint16]bool, len(candidates))
	for _, p := range candidates {
		candidateSet[p] = true
	}

	hits := make(map[netip.Addr]map[uint16]bool, 64)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return hits, probes, nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return nil, probes, err
		}
		if n < 54 {
			continue
		}
		frame := buf[:n]
		if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
			continue
		}
		ip := frame[14:]
		ipHeaderLen := int((ip[0] & 0x0f) * 4)
		if ipHeaderLen < 20 || len(ip) < ipHeaderLen+20 {
			continue
		}
		if ip[9] != 6 {
			continue
		}
		dstIP := netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
		if dstIP != target.srcIP {
			continue
		}
		srcIP := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
		if _, ok := hosts[srcIP]; !ok {
			continue
		}
		tcp := ip[ipHeaderLen:]
		src := binary.BigEndian.Uint16(tcp[0:2])
		dst := binary.BigEndian.Uint16(tcp[2:4])
		flags := tcp[13]
		if dst != srcPort {
			continue
		}
		if flags&0x12 != 0x12 {
			continue
		}
		if !candidateSet[src] {
			continue
		}
		if hits[srcIP] == nil {
			hits[srcIP] = make(map[uint16]bool, 4)
		}
		hits[srcIP][src] = true
	}
	return hits, probes, nil
}

func buildARPRequest(srcMAC []byte, srcIP [4]byte, targetIP [4]byte) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], srcIP[:])
	copy(arp[18:24], []byte{0, 0, 0, 0, 0, 0})
	copy(arp[24:28], targetIP[:])
	return frame
}

func buildTCPSYNPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq uint32) []byte {
	packet := make([]byte, 40)

	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], 40)
	binary.BigEndian.PutUint16(packet[4:6], uint16(seq))
	binary.BigEndian.PutUint16(packet[6:8], 0)
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))

	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = (5 << 4)
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 14600)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)

	psh := make([]byte, 12+20)
	copy(psh[0:4], srcIP[:])
	copy(psh[4:8], dstIP[:])
	psh[8] = 0
	psh[9] = 6
	binary.BigEndian.PutUint16(psh[10:12], 20)
	copy(psh[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(psh))

	return packet
}

func buildTCPSYNFrame(srcMAC []byte, dstMAC []byte, srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq uint32) []byte {
	frame := make([]byte, 54)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], buildTCPSYNPacket(srcIP, dstIP, srcPort, dstPort, seq))
	return frame
}

func buildICMPEchoFrame(srcMAC []byte, srcIP [4]byte, dstIP [4]byte, id uint16, seq uint16) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:34]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], 28)
	binary.BigEndian.PutUint16(ip[4:6], id)
	binary.BigEndian.PutUint16(ip[6:8], 0)
	ip[8] = 64
	ip[9] = 1
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	icmp := frame[34:]
	icmp[0] = 8
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[2:4], 0)
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return frame
}

func idSeqFromIPv4(ip netip.Addr) (uint16, uint16) {
	b := ip.As4()
	id := uint16(b[0])<<8 | uint16(b[1])
	seq := uint16(b[2])<<8 | uint16(b[3])
	return id, seq
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func enrichPermissionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%w (requires root or CAP_NET_RAW)", err)
	}
	return err
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	prev := ""
	for _, s := range in {
		if s != prev {
			out = append(out, s)
			prev = s
		}
	}
	return out
}

func addToIPv4(ip netip.Addr, n uint32) netip.Addr {
	b := ip.As4()
	u := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	u += n
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
