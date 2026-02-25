package node

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultDiscoveryReqTimeout = 2 * time.Second
	maxRTSPResponseBytes       = 64 * 1024
	maxHTTPHeaderReadBytes     = 64 * 1024
	defaultRTSPUserAgent       = "unblink-discovery"
	defaultHTTPUserAgent       = "unblink-discovery"
	rtspServiceType            = "rtsp"
	rtspLockedServiceType      = "rtsp_locked"
	rtspUnknownServiceType     = "rtsp_unknown"
	rtspUnsupportedServiceType = "rtsp_unsupported"
	httpServiceType            = "http"
	mjpegServiceType           = "mjpeg"
	mjpegLockedServiceType     = "mjpeg_locked"
	tcpServiceType             = "tcp"
)

var (
	rtspPortCandidates = []uint16{554, 88, 81, 555, 7447, 8554, 7070, 10554, 80, 6667}
	httpPortCandidates = []uint16{80, 81, 8080, 8081, 8090}
	rtspCodecMarkers   = []string{"H264", "H264-RCDO", "H264-SVC", "MP4V-ES", "MPEG4-GENERIC"}
)

//go:embed discovery_paths/rtsp-paths
var embeddedRTSPPathsData string

//go:embed discovery_paths/mjpeg-paths
var embeddedMJPEGPathsData string

// DiscoveryOptions controls network scanner behavior.
type DiscoveryOptions struct {
	Timeout            time.Duration
	DialTimeout        time.Duration
	ProbeTimeout       time.Duration
	RequestTimeout     time.Duration
	MaxHosts           int
	Workers            int
	IncludeHTTP        bool
	Debug              bool
	InterfaceWhitelist []string
}

// DiscoveryHost represents one discovered host.
type DiscoveryHost struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	ARP  bool   `json:"arp,omitempty"`
	ICMP bool   `json:"icmp,omitempty"`
}

// DiscoveryPort represents one open candidate port.
type DiscoveryPort struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	Port int    `json:"port"`
}

// DiscoveredService represents one discovered service.
type DiscoveredService struct {
	Type string `json:"type"` // rtsp|rtsp_locked|rtsp_unknown|rtsp_unsupported|http|mjpeg|mjpeg_locked|tcp
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	Port int    `json:"port"`
	Path string `json:"path,omitempty"`
	URL  string `json:"url,omitempty"`
}

// DiscoveryScanMeta contains stage counters and durations.
type DiscoveryScanMeta struct {
	Interfaces     []string         `json:"interfaces,omitempty"`
	HostCandidates int              `json:"host_candidates,omitempty"`
	ARPHosts       int              `json:"arp_hosts,omitempty"`
	ICMPHosts      int              `json:"icmp_hosts,omitempty"`
	LiveHosts      int              `json:"live_hosts,omitempty"`
	TCPProbes      int              `json:"tcp_probes,omitempty"`
	OpenPorts      int              `json:"open_ports,omitempty"`
	RTSPServices   int              `json:"rtsp_services,omitempty"`
	HTTPServices   int              `json:"http_services,omitempty"`
	MJPEGServices  int              `json:"mjpeg_services,omitempty"`
	StageMs        map[string]int64 `json:"stage_ms,omitempty"`
}

// DiscoveryReport is the discovery result.
type DiscoveryReport struct {
	StartedAt  string              `json:"started_at"`
	DurationMs int64               `json:"duration_ms"`
	Networks   []string            `json:"networks"`
	Hosts      []DiscoveryHost     `json:"hosts,omitempty"`
	Ports      []DiscoveryPort     `json:"ports,omitempty"`
	Services   []DiscoveredService `json:"services,omitempty"`
	ScanMeta   DiscoveryScanMeta   `json:"scan_meta,omitempty"`
}

type scanHost struct {
	IP   netip.Addr
	MAC  net.HardwareAddr
	ARP  bool
	ICMP bool
}

type openPortScanResult struct {
	Networks       []string
	Interfaces     []string
	HostCandidates int
	Hosts          map[netip.Addr]*scanHost
	OpenPorts      map[netip.Addr]map[uint16]bool
	ARPHosts       int
	ICMPHosts      int
	TCPProbes      int
	StageMs        map[string]int64
}

type discoveredEndpoint struct {
	ip   netip.Addr
	port uint16
}

type rtspResponse struct {
	StatusCode int
	IsRTSP     bool
	Headers    map[string]string
	Body       string
}

type httpResponse struct {
	StatusCode int
	Headers    map[string]string
}

// DiscoverCameras scans local networks for RTSP/MJPEG-like camera services.
func DiscoverCameras(ctx context.Context, opts DiscoveryOptions) (*DiscoveryReport, error) {
	start := time.Now()
	applyDiscoveryDefaults(&opts)

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	rtspPaths := parsePathList(embeddedRTSPPathsData)

	var mjpegPaths []string
	if opts.IncludeHTTP {
		mjpegPaths = parsePathList(embeddedMJPEGPathsData)
	}

	portCandidates := append([]uint16{}, rtspPortCandidates...)
	if opts.IncludeHTTP {
		portCandidates = append(portCandidates, httpPortCandidates...)
	}

	scanStart := time.Now()
	scanResult, err := discoverOpenPorts(ctx, opts, portCandidates)
	if err != nil {
		return nil, err
	}
	stageMs := map[string]int64{
		"open_port_scan": time.Since(scanStart).Milliseconds(),
	}

	report := &DiscoveryReport{
		StartedAt: start.Format(time.RFC3339),
		Networks:  scanResult.Networks,
		ScanMeta: DiscoveryScanMeta{
			Interfaces:     scanResult.Interfaces,
			HostCandidates: scanResult.HostCandidates,
			ARPHosts:       scanResult.ARPHosts,
			ICMPHosts:      scanResult.ICMPHosts,
			LiveHosts:      len(scanResult.Hosts),
			TCPProbes:      scanResult.TCPProbes,
			StageMs:        make(map[string]int64),
		},
	}
	for k, v := range scanResult.StageMs {
		report.ScanMeta.StageMs[k] = v
	}
	for k, v := range stageMs {
		report.ScanMeta.StageMs[k] = v
	}

	if opts.Debug {
		report.Hosts = hostsFromMap(scanResult.Hosts)
		report.Ports = portsFromMap(scanResult.Hosts, scanResult.OpenPorts)
		report.ScanMeta.OpenPorts = len(report.Ports)
	} else {
		report.ScanMeta.OpenPorts = countOpenPorts(scanResult.OpenPorts)
	}

	services := make([]DiscoveredService, 0, 256)

	rtspStart := time.Now()
	rtspServices := prioritizeEndpoints(scanResult.OpenPorts, rtspPortCandidates)
	services = append(services, probeRTSPEndpoints(ctx, scanResult.Hosts, rtspServices, rtspPaths, opts.RequestTimeout, opts.Workers)...)
	report.ScanMeta.StageMs["rtsp_probe"] = time.Since(rtspStart).Milliseconds()

	httpStart := time.Now()
	if opts.IncludeHTTP {
		httpServices := prioritizeEndpoints(scanResult.OpenPorts, httpPortCandidates)
		services = append(services, probeHTTPEndpoints(ctx, scanResult.Hosts, httpServices, mjpegPaths, opts.RequestTimeout, opts.Workers)...)
	}
	report.ScanMeta.StageMs["http_mjpeg_probe"] = time.Since(httpStart).Milliseconds()

	if !opts.Debug {
		report.ScanMeta.StageMs = nil
	}

	report.Services = sortAndDedupeServices(services)
	for _, svc := range report.Services {
		switch svc.Type {
		case rtspServiceType, rtspLockedServiceType, rtspUnknownServiceType, rtspUnsupportedServiceType:
			report.ScanMeta.RTSPServices++
		case httpServiceType:
			report.ScanMeta.HTTPServices++
		case mjpegServiceType, mjpegLockedServiceType:
			report.ScanMeta.MJPEGServices++
		}
	}

	report.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

func applyDiscoveryDefaults(opts *DiscoveryOptions) {
	if opts.RequestTimeout <= 0 {
		if opts.ProbeTimeout > 0 {
			opts.RequestTimeout = opts.ProbeTimeout
		} else {
			opts.RequestTimeout = defaultDiscoveryReqTimeout
		}
	}
	if opts.Workers <= 0 {
		opts.Workers = 64
	}
}

func parsePathList(data string) []string {
	if data == "" {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func hostsFromMap(hosts map[netip.Addr]*scanHost) []DiscoveryHost {
	out := make([]DiscoveryHost, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, DiscoveryHost{
			IP:   host.IP.String(),
			MAC:  formatMAC(host.MAC),
			ARP:  host.ARP,
			ICMP: host.ICMP,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return compareIPStrings(out[i].IP, out[j].IP)
	})
	return out
}

func portsFromMap(hosts map[netip.Addr]*scanHost, openPorts map[netip.Addr]map[uint16]bool) []DiscoveryPort {
	out := make([]DiscoveryPort, 0, 256)
	for ip, ports := range openPorts {
		host := hosts[ip]
		mac := ""
		if host != nil {
			mac = formatMAC(host.MAC)
		}
		for port := range ports {
			out = append(out, DiscoveryPort{
				IP:   ip.String(),
				MAC:  mac,
				Port: int(port),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return compareIPStrings(out[i].IP, out[j].IP)
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func countOpenPorts(openPorts map[netip.Addr]map[uint16]bool) int {
	total := 0
	for _, ports := range openPorts {
		total += len(ports)
	}
	return total
}

func prioritizeEndpoints(openPorts map[netip.Addr]map[uint16]bool, priorities []uint16) []discoveredEndpoint {
	priorityMap := make(map[uint16]int, len(priorities))
	for idx, port := range priorities {
		priorityMap[port] = len(priorities) - idx
	}

	out := make([]discoveredEndpoint, 0, len(openPorts))
	for ip, ports := range openPorts {
		bestPort := uint16(0)
		bestPriority := -1
		for port := range ports {
			score, ok := priorityMap[port]
			if !ok {
				continue
			}
			if score > bestPriority {
				bestPriority = score
				bestPort = port
			}
		}
		if bestPriority >= 0 {
			out = append(out, discoveredEndpoint{ip: ip, port: bestPort})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ip != out[j].ip {
			return out[i].ip.Less(out[j].ip)
		}
		return out[i].port < out[j].port
	})
	return out
}

func probeRTSPEndpoints(
	ctx context.Context,
	hosts map[netip.Addr]*scanHost,
	endpoints []discoveredEndpoint,
	rtspPaths []string,
	timeout time.Duration,
	workers int,
) []DiscoveredService {
	if len(endpoints) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(endpoints) {
		workers = len(endpoints)
	}

	jobs := make(chan discoveredEndpoint, workers*2)
	results := make(chan []DiscoveredService, workers*2)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ep := range jobs {
			host := hosts[ep.ip]
			if host == nil {
				continue
			}
			resp, err := probeRTSPOptions(ctx, ep.ip, ep.port, timeout)
			if err != nil || resp.StatusCode == 0 || !resp.IsRTSP {
				continue
			}

			list := []DiscoveredService{
				{
					Type: tcpServiceType,
					IP:   ep.ip.String(),
					MAC:  formatMAC(host.MAC),
					Port: int(ep.port),
					URL:  fmt.Sprintf("tcp://%s:%d", ep.ip, ep.port),
				},
				findRTSPService(ctx, ep, host, rtspPaths, timeout),
			}
			for _, svc := range list {
				logDiscoveryServiceHit(svc)
			}

			select {
			case results <- list:
			case <-ctx.Done():
				return
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, ep := range endpoints {
			select {
			case jobs <- ep:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]DiscoveredService, 0, len(endpoints)*2)
	for list := range results {
		out = append(out, list...)
	}
	return out
}

func probeHTTPEndpoints(
	ctx context.Context,
	hosts map[netip.Addr]*scanHost,
	endpoints []discoveredEndpoint,
	mjpegPaths []string,
	timeout time.Duration,
	workers int,
) []DiscoveredService {
	if len(endpoints) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(endpoints) {
		workers = len(endpoints)
	}

	jobs := make(chan discoveredEndpoint, workers*2)
	results := make(chan []DiscoveredService, workers*2)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ep := range jobs {
			host := hosts[ep.ip]
			if host == nil {
				continue
			}
			resp, err := getHTTPResponse(ctx, ep.ip, ep.port, "/", timeout)
			if err != nil || resp.StatusCode == 0 {
				continue
			}

			list := []DiscoveredService{
				{
					Type: httpServiceType,
					IP:   ep.ip.String(),
					MAC:  formatMAC(host.MAC),
					Port: int(ep.port),
					URL:  fmt.Sprintf("http://%s:%d", ep.ip, ep.port),
				},
			}
			logDiscoveryServiceHit(list[0])
			if svc, ok := findMJPEGService(ctx, ep, host, mjpegPaths, timeout, workers); ok {
				list = append(list, svc)
				logDiscoveryServiceHit(svc)
			}

			select {
			case results <- list:
			case <-ctx.Done():
				return
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, ep := range endpoints {
			select {
			case jobs <- ep:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]DiscoveredService, 0, len(endpoints))
	for list := range results {
		out = append(out, list...)
	}
	return out
}

func findRTSPService(ctx context.Context, ep discoveredEndpoint, host *scanHost, paths []string, timeout time.Duration) DiscoveredService {
	base := DiscoveredService{
		IP:   ep.ip.String(),
		MAC:  formatMAC(host.MAC),
		Port: int(ep.port),
	}

	if len(paths) == 0 {
		base.Type = rtspUnknownServiceType
		base.URL = fmt.Sprintf("rtsp://%s:%d", ep.ip, ep.port)
		return base
	}

	result := base
	result.Type = rtspUnknownServiceType
	result.URL = fmt.Sprintf("rtsp://%s:%d", ep.ip, ep.port)

	for _, path := range paths {
		resp, err := probeRTSPDescribe(ctx, ep.ip, ep.port, path, timeout)
		if err != nil {
			continue
		}

		if isHiIpcamServer(resp.Headers["server"]) && path != "/11" && path != "/12" {
			continue
		}

		switch {
		case resp.StatusCode == 200 && isSupportedRTSPService(resp.Body):
			return DiscoveredService{
				Type: rtspServiceType,
				IP:   ep.ip.String(),
				MAC:  formatMAC(host.MAC),
				Port: int(ep.port),
				Path: path,
				URL:  fmt.Sprintf("rtsp://%s:%d%s", ep.ip, ep.port, path),
			}
		case resp.StatusCode == 200:
			result.Type = rtspUnsupportedServiceType
			result.Path = path
			result.URL = fmt.Sprintf("rtsp://%s:%d%s", ep.ip, ep.port, path)
		case resp.StatusCode == 401:
			return DiscoveredService{
				Type: rtspLockedServiceType,
				IP:   ep.ip.String(),
				MAC:  formatMAC(host.MAC),
				Port: int(ep.port),
				URL:  fmt.Sprintf("rtsp://%s:%d", ep.ip, ep.port),
			}
		}
	}
	return result
}

func findMJPEGService(
	ctx context.Context,
	ep discoveredEndpoint,
	host *scanHost,
	paths []string,
	timeout time.Duration,
	_ int,
) (DiscoveredService, bool) {
	return findMJPEGServiceSequential(ctx, ep, host, paths, timeout)
}

func findMJPEGServiceSequential(ctx context.Context, ep discoveredEndpoint, host *scanHost, paths []string, timeout time.Duration) (DiscoveredService, bool) {
	for _, path := range paths {
		resp, err := getHTTPResponse(ctx, ep.ip, ep.port, path, timeout)
		if err != nil {
			continue
		}
		switch {
		case resp.StatusCode == 200 && isSupportedMJPEGService(resp.Headers["content-type"]):
			return DiscoveredService{
				Type: mjpegServiceType,
				IP:   ep.ip.String(),
				MAC:  formatMAC(host.MAC),
				Port: int(ep.port),
				Path: path,
				URL:  fmt.Sprintf("http://%s:%d%s", ep.ip, ep.port, path),
			}, true
		case resp.StatusCode == 401:
			return DiscoveredService{
				Type: mjpegLockedServiceType,
				IP:   ep.ip.String(),
				MAC:  formatMAC(host.MAC),
				Port: int(ep.port),
				URL:  fmt.Sprintf("http://%s:%d", ep.ip, ep.port),
			}, true
		}
	}
	return DiscoveredService{}, false
}

func logDiscoveryServiceHit(svc DiscoveredService) {
	if svc.Type == "" {
		return
	}
	log.Printf(
		"[Discovery][HIT] service type=%s ip=%s port=%d path=%q url=%q",
		svc.Type,
		svc.IP,
		svc.Port,
		svc.Path,
		svc.URL,
	)
}

func probeRTSPOptions(ctx context.Context, ip netip.Addr, port uint16, timeout time.Duration) (rtspResponse, error) {
	raw, err := sendRTSP(ctx, ip, port, "/", "OPTIONS", timeout)
	if err != nil {
		return rtspResponse{}, err
	}
	return parseRTSPResponse(raw), nil
}

func probeRTSPDescribe(ctx context.Context, ip netip.Addr, port uint16, path string, timeout time.Duration) (rtspResponse, error) {
	raw, err := sendRTSP(ctx, ip, port, path, "DESCRIBE", timeout)
	if err != nil {
		return rtspResponse{}, err
	}
	return parseRTSPResponse(raw), nil
}

func sendRTSP(ctx context.Context, ip netip.Addr, port uint16, path, method string, timeout time.Duration) (string, error) {
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	uri := fmt.Sprintf("rtsp://%s:%d%s", ip, port, path)
	req := fmt.Sprintf("%s %s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: %s\r\nAccept: application/sdp\r\n\r\n", method, uri, defaultRTSPUserAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 0, 4096)
	for len(buf) < maxRTSPResponseBytes {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			buf = append(buf, line...)
			if strings.Contains(string(buf), "\r\n\r\n") && method == "OPTIONS" {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return string(buf), nil
}

func parseRTSPResponse(raw string) rtspResponse {
	headers := make(map[string]string)
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 1 && strings.Contains(head, "\n") {
		lines = strings.Split(head, "\n")
	}

	statusCode := 0
	isRTSP := false
	if len(lines) > 0 {
		isRTSP = strings.HasPrefix(lines[0], "RTSP/")
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			statusCode, _ = strconv.Atoi(fields[1])
		}
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return rtspResponse{
		StatusCode: statusCode,
		IsRTSP:     isRTSP,
		Headers:    headers,
		Body:       body,
	}
}

func isSupportedRTSPService(sdp string) bool {
	sdpUpper := strings.ToUpper(sdp)
	for _, marker := range rtspCodecMarkers {
		if strings.Contains(sdpUpper, marker) {
			return true
		}
	}
	return false
}

func isHiIpcamServer(server string) bool {
	return server == "HiIpcam/V100R003 VodServer/1.0.0" || server == "Hipcam RealServer/V1.0"
}

func getHTTPResponse(ctx context.Context, ip netip.Addr, port uint16, path string, timeout time.Duration) (httpResponse, error) {
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return httpResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", path, ip.String(), defaultHTTPUserAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return httpResponse{}, err
	}

	reader := bufio.NewReader(conn)
	raw := make([]byte, 0, 2048)
	for len(raw) < maxHTTPHeaderReadBytes {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			raw = append(raw, line...)
			if strings.Contains(string(raw), "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			break
		}
	}

	headers := make(map[string]string)
	text := string(raw)
	head, _, _ := strings.Cut(text, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 1 && strings.Contains(head, "\n") {
		lines = strings.Split(head, "\n")
	}

	status := 0
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			status, _ = strconv.Atoi(fields[1])
		}
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return httpResponse{
		StatusCode: status,
		Headers:    headers,
	}, nil
}

func isSupportedMJPEGService(contentType string) bool {
	ctype := strings.ToLower(contentType)
	return strings.HasPrefix(ctype, "multipart/x-mixed-replace") ||
		strings.HasPrefix(ctype, "image/jpeg") ||
		strings.HasPrefix(ctype, "image/jpg")
}

func sortAndDedupeServices(in []DiscoveredService) []DiscoveredService {
	sort.Slice(in, func(i, j int) bool {
		if in[i].IP != in[j].IP {
			return compareIPStrings(in[i].IP, in[j].IP)
		}
		if in[i].Port != in[j].Port {
			return in[i].Port < in[j].Port
		}
		if in[i].Type != in[j].Type {
			return in[i].Type < in[j].Type
		}
		if in[i].Path != in[j].Path {
			return in[i].Path < in[j].Path
		}
		return in[i].URL < in[j].URL
	})

	seen := make(map[string]bool, len(in))
	out := make([]DiscoveredService, 0, len(in))
	for _, svc := range in {
		key := svc.Type + "|" + svc.IP + "|" + strconv.Itoa(svc.Port) + "|" + svc.Path + "|" + svc.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, svc)
	}
	return out
}

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return ""
	}
	return mac.String()
}

func compareIPStrings(a, b string) bool {
	ia, ea := netip.ParseAddr(a)
	ib, eb := netip.ParseAddr(b)
	if ea == nil && eb == nil {
		return ia.Less(ib)
	}
	return a < b
}

// DiscoveryReportJSON returns pretty JSON for CLI output.
func DiscoveryReportJSON(report *DiscoveryReport) string {
	data, _ := json.MarshalIndent(report, "", "  ")
	return string(data)
}
