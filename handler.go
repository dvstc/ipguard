package ipguard

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// HandlerOption configures the HTTP middleware returned by WrapHandler.
type HandlerOption func(*handlerConfig)

type handlerConfig struct {
	trustedProxies []net.IPNet
	ipHeader       string
	extractor      func(*http.Request) string
	failureCodes   map[int]bool
	transport      string
}

// WithTrustedProxies declares which CIDRs are trusted reverse proxies.
// Only requests arriving from these IPs will have their forwarding
// headers consulted for the real client IP.
func WithTrustedProxies(cidrs ...string) HandlerOption {
	return func(c *handlerConfig) {
		c.trustedProxies = nil
		for _, entry := range cidrs {
			if _, network, err := net.ParseCIDR(entry); err == nil {
				c.trustedProxies = append(c.trustedProxies, *network)
			} else if ip := net.ParseIP(entry); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					c.trustedProxies = append(c.trustedProxies, net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
				} else {
					c.trustedProxies = append(c.trustedProxies, net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
				}
			} else {
				c.trustedProxies = append(c.trustedProxies, net.IPNet{})
			}
		}
	}
}

// WithIPHeader sets the HTTP header to read for the real client IP
// (e.g. "X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP").
// Requires WithTrustedProxies to also be set.
func WithIPHeader(header string) HandlerOption {
	return func(c *handlerConfig) { c.ipHeader = header }
}

// WithIPExtractor sets a custom function to extract the client IP from
// the request. When set, trusted proxy validation is bypassed entirely.
func WithIPExtractor(fn func(*http.Request) string) HandlerOption {
	return func(c *handlerConfig) { c.extractor = fn }
}

// WithFailureCodes configures HTTP status codes that automatically
// trigger RecordFailure after the inner handler responds (e.g. 401, 404).
func WithFailureCodes(codes ...int) HandlerOption {
	return func(c *handlerConfig) {
		c.failureCodes = make(map[int]bool, len(codes))
		for _, code := range codes {
			c.failureCodes[code] = true
		}
	}
}

// WithTransport overrides the auto-detected transport string.
// By default, transport is "https" when r.TLS != nil, "http" otherwise.
func WithTransport(transport string) HandlerOption {
	return func(c *handlerConfig) { c.transport = transport }
}

// WrapHandler returns an http.Handler that checks IsBlocked before
// passing requests to h, and optionally records failures based on
// response status codes. Returns an error if options are misconfigured.
func (g *Guard) WrapHandler(h http.Handler, opts ...HandlerOption) (http.Handler, error) {
	if g == nil {
		return h, nil
	}

	cfg := &handlerConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.extractor == nil && cfg.ipHeader != "" && len(cfg.trustedProxies) == 0 {
		return nil, fmt.Errorf("ipguard: WithIPHeader(%q) requires WithTrustedProxies", cfg.ipHeader)
	}

	if cfg.extractor == nil {
		for _, n := range cfg.trustedProxies {
			if n.IP == nil {
				return nil, fmt.Errorf("ipguard: invalid CIDR in WithTrustedProxies")
			}
		}
	}

	extract := cfg.buildExtractor()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extract(r)

		transport := cfg.transport
		if transport == "" {
			if r.TLS != nil {
				transport = "https"
			} else {
				transport = "http"
			}
		}

		if blocked, reason := g.IsBlocked(ip); blocked {
			g.logBlocked(ip, reason, transport)
			w.Header().Set("X-Blocked-Reason", reason)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if len(cfg.failureCodes) > 0 {
			sr := &statusRecorder{ResponseWriter: w, status: 200}
			h.ServeHTTP(sr, r)
			if cfg.failureCodes[sr.status] {
				g.RecordFailure(ip, transport)
			}
		} else {
			h.ServeHTTP(w, r)
		}
	}), nil
}

func (c *handlerConfig) buildExtractor() func(*http.Request) string {
	if c.extractor != nil {
		return c.extractor
	}

	if c.ipHeader != "" && len(c.trustedProxies) > 0 {
		proxies := c.trustedProxies
		header := c.ipHeader
		return func(r *http.Request) string {
			remoteIP := extractAddrIP(r.RemoteAddr)
			if !isTrustedProxy(remoteIP, proxies) {
				return remoteIP
			}
			return extractFromHeader(r.Header.Get(header), proxies, remoteIP)
		}
	}

	return func(r *http.Request) string {
		return extractAddrIP(r.RemoteAddr)
	}
}

func extractFromHeader(headerVal string, proxies []net.IPNet, fallback string) string {
	if headerVal == "" {
		return fallback
	}

	parts := strings.Split(headerVal, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		if !isTrustedProxy(candidate, proxies) {
			return candidate
		}
	}
	return fallback
}

func isTrustedProxy(ip string, proxies []net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if p4 := parsed.To4(); p4 != nil {
		parsed = p4
	}
	for i := range proxies {
		if proxies[i].Contains(parsed) {
			return true
		}
	}
	return false
}

func extractAddrIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wroteHeader {
		sr.status = code
		sr.wroteHeader = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wroteHeader {
		sr.wroteHeader = true
	}
	return sr.ResponseWriter.Write(b)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sr.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("ipguard: underlying ResponseWriter does not support Hijack")
}
