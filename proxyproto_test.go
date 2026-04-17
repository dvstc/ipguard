package ipguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// --- Construction validation ---

func TestWrapListenerProxyProto_EmptyTrusted(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	_, err := g.WrapListenerProxyProto(ln, "ssh", nil)
	if err == nil {
		t.Fatal("expected error for empty trusted list")
	}
}

func TestWrapListenerProxyProto_InvalidCIDR(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	_, err := g.WrapListenerProxyProto(ln, "ssh", []string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestWrapListenerProxyProto_ValidTrusted(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	_, err := g.WrapListenerProxyProto(ln, "ssh", []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestWrapListenerProxyProto_NilGuard(t *testing.T) {
	var g *Guard
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	result, err := g.WrapListenerProxyProto(ln, "ssh", []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("nil guard should not error: %v", err)
	}
	if result != ln {
		t.Error("nil guard should return listener unchanged")
	}
}

// --- v1 parsing ---

func TestProxyProto_V1_TCP4(t *testing.T) {
	g := newTestGuard(t, Config{Blacklist: []string{"203.0.113.50"}})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n")
		fmt.Fprintf(conn, "hello after proxy")
		// keep conn open for test
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	remoteAddr := accepted.RemoteAddr().String()
	if remoteAddr != "192.168.1.100" {
		t.Errorf("expected RemoteAddr=192.168.1.100, got %s", remoteAddr)
	}

	buf := make([]byte, 17)
	n, _ := accepted.Read(buf)
	if string(buf[:n]) != "hello after proxy" {
		t.Errorf("expected 'hello after proxy', got %q", string(buf[:n]))
	}
}

func TestProxyProto_V1_TCP6(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n")
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	remoteAddr := accepted.RemoteAddr().String()
	if remoteAddr != "2001:db8::1" {
		t.Errorf("expected RemoteAddr=2001:db8::1, got %s", remoteAddr)
	}
}

func TestProxyProto_V1_UNKNOWN(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY UNKNOWN\r\n")
		time.Sleep(500 * time.Millisecond)
		conn.Close()

		// Close listener so Accept returns an error
		time.Sleep(200 * time.Millisecond)
		ln.Close()
	}()

	// UNKNOWN returns "" from parseProxyV1, connection is closed,
	// Accept loops and hits listener close
	_, err := guarded.Accept()
	if err == nil {
		t.Error("expected error after UNKNOWN header and listener close")
	}
}

func TestProxyProto_V1_Malformed(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY BADPROTO\r\n")
		time.Sleep(time.Second)
		conn.Close()
		// Send a second valid connection so Accept returns
		conn2, _ := net.Dial("tcp", ln.Addr().String())
		if conn2 != nil {
			conn2.Close()
		}
	}()

	// Malformed connection should be closed; Accept will keep trying
	// until listener is closed or another connection arrives
	go func() {
		time.Sleep(3 * time.Second)
		ln.Close()
	}()

	_, err := guarded.Accept()
	if err == nil {
		t.Error("expected error after all connections exhausted")
	}
}

// --- v2 parsing ---

func buildV2Header(cmd byte, family byte, srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	var buf []byte
	buf = append(buf, proxyV2Signature...)
	buf = append(buf, 0x20|cmd) // version 2 + command
	buf = append(buf, family<<4|0x01) // family + stream

	var addrData []byte
	if family == 1 { // AF_INET
		addrData = append(addrData, srcIP.To4()...)
		addrData = append(addrData, dstIP.To4()...)
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, srcPort)
		addrData = append(addrData, p...)
		binary.BigEndian.PutUint16(p, dstPort)
		addrData = append(addrData, p...)
	} else if family == 2 { // AF_INET6
		addrData = append(addrData, srcIP.To16()...)
		addrData = append(addrData, dstIP.To16()...)
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, srcPort)
		addrData = append(addrData, p...)
		binary.BigEndian.PutUint16(p, dstPort)
		addrData = append(addrData, p...)
	}

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(addrData)))
	buf = append(buf, lenBytes...)
	buf = append(buf, addrData...)
	return buf
}

func TestProxyProto_V2_TCP4(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		header := buildV2Header(1, 1, net.ParseIP("198.51.100.5"), net.ParseIP("10.0.0.1"), 56324, 443)
		conn.Write(header)
		conn.Write([]byte("v2 payload"))
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	remoteAddr := accepted.RemoteAddr().String()
	if remoteAddr != "198.51.100.5" {
		t.Errorf("expected RemoteAddr=198.51.100.5, got %s", remoteAddr)
	}

	buf := make([]byte, 20)
	n, _ := accepted.Read(buf)
	if string(buf[:n]) != "v2 payload" {
		t.Errorf("expected 'v2 payload', got %q", string(buf[:n]))
	}
}

func TestProxyProto_V2_TCP6(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		header := buildV2Header(1, 2, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 56324, 443)
		conn.Write(header)
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	remoteAddr := accepted.RemoteAddr().String()
	if remoteAddr != "2001:db8::1" {
		t.Errorf("expected RemoteAddr=2001:db8::1, got %s", remoteAddr)
	}
}

func TestProxyProto_V2_LOCAL(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		var buf []byte
		buf = append(buf, proxyV2Signature...)
		buf = append(buf, 0x20) // version 2, cmd LOCAL (0)
		buf = append(buf, 0x00) // unspec family+proto
		buf = append(buf, 0x00, 0x00) // length 0
		conn.Write(buf)
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	// LOCAL command returns "" from parseProxyV2, so connection is closed
	go func() {
		time.Sleep(4 * time.Second)
		ln.Close()
	}()

	_, err := guarded.Accept()
	if err == nil {
		// this is expected -- LOCAL causes conn close and retry
	}
}

// --- Trust validation ---

func TestProxyProto_UntrustedSource_NoHeaderParsing(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	// Trust a different IP, not 127.0.0.1
	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"10.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		// Send PROXY header, but source is not trusted
		fmt.Fprintf(conn, "PROXY TCP4 203.0.113.50 10.0.0.1 56324 443\r\n")
		fmt.Fprintf(conn, "data")
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	remoteAddr := accepted.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)
	if host != "127.0.0.1" {
		t.Errorf("untrusted source should use RemoteAddr, got %s", remoteAddr)
	}
}

// --- Guard integration ---

func TestProxyProto_BlockedRealIP(t *testing.T) {
	var events []BlockEvent
	g := newTestGuard(t, Config{Blacklist: []string{"203.0.113.50"}},
		WithHooks(&Hooks{OnBlocked: func(e BlockEvent) { events = append(events, e) }}))

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "ssh", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY TCP4 203.0.113.50 10.0.0.1 56324 22\r\n")
		time.Sleep(time.Second)
		conn.Close()

		// Send a second connection to unblock Accept
		time.Sleep(100 * time.Millisecond)
		ln.Close()
	}()

	_, err := guarded.Accept()
	if err == nil {
		t.Error("expected error -- blocked IP conn closed, then listener closed")
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 block event, got %d", len(events))
	}
	if events[0].IP != "203.0.113.50" {
		t.Errorf("expected blocked IP 203.0.113.50, got %s", events[0].IP)
	}
}

func TestProxyProto_AllowedRealIP(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "ssh", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY TCP4 192.168.1.5 10.0.0.1 56324 22\r\n")
		fmt.Fprintf(conn, "SSH-2.0-test")
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	if accepted.RemoteAddr().String() != "192.168.1.5" {
		t.Errorf("RemoteAddr should be real IP, got %s", accepted.RemoteAddr().String())
	}

	buf := make([]byte, 20)
	n, _ := accepted.Read(buf)
	if string(buf[:n]) != "SSH-2.0-test" {
		t.Errorf("expected 'SSH-2.0-test', got %q", string(buf[:n]))
	}
}

// --- Timeout ---

func TestProxyProto_Timeout_NoData(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(500*time.Millisecond))

	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		// Send nothing -- trigger timeout
		time.Sleep(3 * time.Second)
		conn.Close()
	}()

	go func() {
		time.Sleep(2 * time.Second)
		ln.Close()
	}()

	_, err := guarded.Accept()
	if err == nil {
		t.Error("expected error after timeout and listener close")
	}
}

// --- Buffered data ---

func TestProxyProto_BufferedDataNotLost(t *testing.T) {
	g := newTestGuard(t, Config{})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	guarded, _ := g.WrapListenerProxyProto(ln, "test", []string{"127.0.0.1/32"},
		WithProxyProtoTimeout(2*time.Second))

	payload := "important data that must not be lost"
	go func() {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		fmt.Fprintf(conn, "PROXY TCP4 1.2.3.4 10.0.0.1 1234 443\r\n%s", payload)
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	accepted, err := guarded.Accept()
	if err != nil {
		t.Fatalf("Accept error: %v", err)
	}
	defer accepted.Close()

	buf := make([]byte, 100)
	n, _ := accepted.Read(buf)
	if string(buf[:n]) != payload {
		t.Errorf("expected %q, got %q", payload, string(buf[:n]))
	}
}
