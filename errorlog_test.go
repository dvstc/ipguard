package ipguard

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestWrapErrorLog_NilGuard(t *testing.T) {
	var g *Guard

	t.Run("nil fallback returns nil", func(t *testing.T) {
		if got := g.WrapErrorLog(nil); got != nil {
			t.Fatal("expected nil logger for nil guard + nil fallback")
		}
	})

	t.Run("non-nil fallback returned unchanged", func(t *testing.T) {
		fb := log.New(&bytes.Buffer{}, "", 0)
		if got := g.WrapErrorLog(fb); got != fb {
			t.Fatal("expected fallback logger returned as-is for nil guard")
		}
	})
}

func TestWrapErrorLog_IPExtraction(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		wantIP   string
		wantFail bool // whether RecordFailure should be called
	}{
		{
			name:     "unsupported TLS version",
			msg:      "http: TLS handshake error from 45.33.69.253:36122: tls: client offered only unsupported versions: [301]",
			wantIP:   "45.33.69.253",
			wantFail: true,
		},
		{
			name:     "missing server name",
			msg:      "http: TLS handshake error from 45.33.69.253:36128: acme/autocert: missing server name",
			wantIP:   "45.33.69.253",
			wantFail: true,
		},
		{
			name:     "EOF",
			msg:      "http: TLS handshake error from 59.52.102.111:34351: EOF",
			wantIP:   "59.52.102.111",
			wantFail: true,
		},
		{
			name:     "HTTP to HTTPS",
			msg:      "http: TLS handshake error from 101.249.60.41:30140: client sent an HTTP request to an HTTPS server",
			wantIP:   "101.249.60.41",
			wantFail: true,
		},
		{
			name:     "first record not TLS",
			msg:      "http: TLS handshake error from 123.232.132.142:36901: tls: first record does not look like a TLS handshake",
			wantIP:   "123.232.132.142",
			wantFail: true,
		},
		{
			name:     "connection reset with nested colons",
			msg:      "http: TLS handshake error from 45.33.69.253:36142: read tcp 172.18.0.2:443->45.33.69.253:36142: read: connection reset by peer",
			wantIP:   "45.33.69.253",
			wantFail: true,
		},
		{
			name:     "accept error (non-TLS)",
			msg:      "http: Accept error: accept tcp 0.0.0.0:443: too many open files",
			wantFail: false,
		},
		{
			name:     "empty message",
			msg:      "",
			wantFail: false,
		},
		{
			name:     "unrelated server error",
			msg:      "http: response.WriteHeader on hijacked connection from main.handler (server.go:42)",
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newTestGuard(t, Config{
				MaxRetry: 10,
				FindTime: time.Minute,
				BanTime:  time.Hour,
			})
			logger := g.WrapErrorLog(nil)

			logger.Printf("%s", tt.msg)

			g.mu.RLock()
			rec := g.records[tt.wantIP]
			g.mu.RUnlock()

			if tt.wantFail {
				if rec == nil {
					t.Fatalf("expected failure recorded for %s, got no record", tt.wantIP)
				}
				if len(rec.failures) != 1 {
					t.Fatalf("expected 1 failure, got %d", len(rec.failures))
				}
			} else {
				if rec != nil && len(rec.failures) > 0 {
					t.Fatal("expected no failure recorded for non-TLS message")
				}
			}
		})
	}
}

func TestWrapErrorLog_FallbackForwarding(t *testing.T) {
	t.Run("messages forwarded to fallback", func(t *testing.T) {
		g := newTestGuard(t, Config{
			MaxRetry: 10,
			FindTime: time.Minute,
			BanTime:  time.Hour,
		})

		var buf bytes.Buffer
		fallback := log.New(&buf, "", 0)
		logger := g.WrapErrorLog(fallback)

		logger.Printf("http: TLS handshake error from 1.2.3.4:5678: EOF")
		logger.Printf("http: Accept error: too many open files")

		output := buf.String()
		if !strings.Contains(output, "TLS handshake error from 1.2.3.4:5678") {
			t.Error("TLS message not forwarded to fallback")
		}
		if !strings.Contains(output, "Accept error: too many open files") {
			t.Error("non-TLS message not forwarded to fallback")
		}
	})

	t.Run("fallback receives messages not guard logger", func(t *testing.T) {
		var guardBuf bytes.Buffer
		guardLogger := log.New(&guardBuf, "", 0)

		g := newTestGuard(t, Config{
			MaxRetry: 10,
			FindTime: time.Minute,
			BanTime:  time.Hour,
		}, WithLogger(guardLogger))

		var fallbackBuf bytes.Buffer
		fallback := log.New(&fallbackBuf, "", 0)
		logger := g.WrapErrorLog(fallback)

		logger.Printf("http: Accept error: too many open files")

		if !strings.Contains(fallbackBuf.String(), "Accept error") {
			t.Error("message not forwarded to fallback")
		}
		// Guard logger should only have RecordFailure output, not the forwarded message.
		// Since this is a non-TLS message, guard logger should have nothing.
		if strings.Contains(guardBuf.String(), "Accept error") {
			t.Error("non-TLS message leaked to guard logger when fallback is set")
		}
	})

	t.Run("nil fallback forwards to guard logger", func(t *testing.T) {
		var guardBuf bytes.Buffer
		guardLogger := log.New(&guardBuf, "", 0)

		g := newTestGuard(t, Config{
			MaxRetry: 10,
			FindTime: time.Minute,
			BanTime:  time.Hour,
		}, WithLogger(guardLogger))

		logger := g.WrapErrorLog(nil)

		logger.Printf("http: Accept error: too many open files")

		if !strings.Contains(guardBuf.String(), "Accept error") {
			t.Error("message not forwarded to guard logger when fallback is nil")
		}
	})

	t.Run("nil fallback and no guard logger does not panic", func(t *testing.T) {
		g := newTestGuard(t, Config{
			MaxRetry: 10,
			FindTime: time.Minute,
			BanTime:  time.Hour,
		})

		logger := g.WrapErrorLog(nil)
		logger.Printf("http: TLS handshake error from 1.2.3.4:5678: EOF")
		logger.Printf("http: Accept error: too many open files")
	})
}

func TestWrapErrorLog_AutoBanIntegration(t *testing.T) {
	now := time.Now()
	g := newTestGuard(t, Config{
		MaxRetry: 5,
		FindTime: time.Minute,
		BanTime:  time.Hour,
	}, WithClock(func() time.Time { return now }))

	logger := g.WrapErrorLog(nil)

	for i := 0; i < 5; i++ {
		logger.Printf("http: TLS handshake error from 45.33.69.253:%d: acme/autocert: missing server name", 36100+i)
	}

	if blocked, reason := g.IsBlocked("45.33.69.253"); !blocked {
		t.Fatal("expected IP to be auto-banned after 5 TLS failures")
	} else if reason != ReasonAutoBan {
		t.Fatalf("expected reason %q, got %q", ReasonAutoBan, reason)
	}
}
