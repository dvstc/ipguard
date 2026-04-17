package ipguard

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ProxyProtoOption configures the PROXY protocol listener.
type ProxyProtoOption func(*proxyProtoConfig)

type proxyProtoConfig struct {
	timeout time.Duration
}

// WithProxyProtoTimeout sets the read deadline for parsing the PROXY
// protocol header from trusted sources. Default is 5 seconds.
func WithProxyProtoTimeout(d time.Duration) ProxyProtoOption {
	return func(c *proxyProtoConfig) { c.timeout = d }
}

type proxyProtoListener struct {
	net.Listener
	guard   *Guard
	transport string
	trusted []net.IPNet
	timeout time.Duration
}

// WrapListenerProxyProto wraps a net.Listener to decode PROXY protocol
// v1/v2 headers from trusted proxy sources and filter connections using
// the real client IP. The trusted parameter is required and must contain
// at least one valid CIDR or IP for the upstream load balancer(s).
func (g *Guard) WrapListenerProxyProto(ln net.Listener, transport string, trusted []string, opts ...ProxyProtoOption) (net.Listener, error) {
	if g == nil {
		return ln, nil
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("ipguard: WrapListenerProxyProto requires at least one trusted proxy CIDR")
	}

	nets, err := parseCIDRList(trusted)
	if err != nil {
		return nil, fmt.Errorf("ipguard: trusted proxies: %w", err)
	}

	cfg := &proxyProtoConfig{timeout: 5 * time.Second}
	for _, opt := range opts {
		opt(cfg)
	}

	return &proxyProtoListener{
		Listener:  ln,
		guard:     g,
		transport: transport,
		trusted:   nets,
		timeout:   cfg.timeout,
	}, nil
}

func (pl *proxyProtoListener) Accept() (net.Conn, error) {
	for {
		conn, err := pl.Listener.Accept()
		if err != nil {
			return nil, err
		}

		resolved, clientIP := pl.resolveConn(conn)
		if resolved == nil {
			continue
		}

		if blocked, reason := pl.guard.IsBlocked(clientIP); blocked {
			pl.guard.logBlocked(clientIP, reason, pl.transport)
			resolved.Close()
			continue
		}

		return resolved, nil
	}
}

// resolveConn decodes the PROXY header if the source is trusted,
// returning the (possibly wrapped) connection and the real client IP.
// Returns (nil, "") if the connection was closed due to a parse error.
func (pl *proxyProtoListener) resolveConn(conn net.Conn) (net.Conn, string) {
	remoteIP := extractConnIP(conn)
	parsed := net.ParseIP(remoteIP)
	if parsed == nil {
		return conn, remoteIP
	}
	if p4 := parsed.To4(); p4 != nil {
		parsed = p4
	}

	if !matchesAny(parsed, pl.trusted) {
		return conn, remoteIP
	}

	conn.SetReadDeadline(time.Now().Add(pl.timeout))

	br := bufio.NewReaderSize(conn, 256)
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return nil, ""
	}

	var realIP string
	switch first[0] {
	case 'P':
		realIP = parseProxyV1(br)
	case '\r':
		realIP = parseProxyV2(br)
	default:
		conn.Close()
		return nil, ""
	}

	conn.SetReadDeadline(time.Time{})

	if realIP == "" {
		conn.Close()
		return nil, ""
	}

	wrapped := &proxyConn{Conn: conn, reader: br, addr: &proxyAddr{ip: realIP}}
	return wrapped, realIP
}

func extractConnIP(conn net.Conn) string {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// --- PROXY protocol v1 parser ---

var proxyV1Signature = "PROXY "

func parseProxyV1(br *bufio.Reader) string {
	line, err := br.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimRight(line, "\r\n")

	if !strings.HasPrefix(line, proxyV1Signature) {
		return ""
	}

	fields := strings.Split(line, " ")
	if len(fields) < 3 {
		return ""
	}

	proto := fields[1]
	if proto == "UNKNOWN" {
		return ""
	}
	if proto != "TCP4" && proto != "TCP6" {
		return ""
	}

	srcIP := fields[2]
	if net.ParseIP(srcIP) == nil {
		return ""
	}

	return srcIP
}

// --- PROXY protocol v2 parser ---

var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

func parseProxyV2(br *bufio.Reader) string {
	header := make([]byte, 16)
	if _, err := io.ReadFull(br, header); err != nil {
		return ""
	}

	for i := 0; i < 12; i++ {
		if header[i] != proxyV2Signature[i] {
			return ""
		}
	}

	verCmd := header[12]
	version := verCmd >> 4
	cmd := verCmd & 0x0F

	if version != 2 {
		return ""
	}

	famProto := header[13]
	addrLen := binary.BigEndian.Uint16(header[14:16])

	addrData := make([]byte, addrLen)
	if _, err := io.ReadFull(br, addrData); err != nil {
		return ""
	}

	if cmd == 0 {
		return ""
	}

	addrFamily := famProto >> 4

	switch addrFamily {
	case 1: // AF_INET
		if len(addrData) < 12 {
			return ""
		}
		srcIP := net.IPv4(addrData[0], addrData[1], addrData[2], addrData[3])
		return srcIP.String()
	case 2: // AF_INET6
		if len(addrData) < 36 {
			return ""
		}
		srcIP := net.IP(addrData[0:16])
		return srcIP.String()
	default:
		return ""
	}
}

// --- proxyConn wraps net.Conn with overridden RemoteAddr and buffered reader ---

type proxyAddr struct {
	ip string
}

func (a *proxyAddr) Network() string { return "tcp" }
func (a *proxyAddr) String() string  { return a.ip }

type proxyConn struct {
	net.Conn
	reader *bufio.Reader
	addr   *proxyAddr
}

func (pc *proxyConn) RemoteAddr() net.Addr {
	return pc.addr
}

func (pc *proxyConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}
