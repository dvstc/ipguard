package ipguard

import (
	"bytes"
	"log"
	"net"
	"strings"
)

// WrapErrorLog returns a *log.Logger suitable for http.Server.ErrorLog.
// It intercepts Go's TLS handshake error messages, extracts the client IP,
// and calls RecordFailure so the existing auto-ban logic can act on repeated
// TLS failures (scanners probing with bad SNI, unsupported versions, etc.).
//
// The fallback logger receives all messages (TLS and non-TLS) at whatever
// level the consumer configured. If fallback is nil, messages are forwarded
// to the guard's own logger (set via WithLogger). If both are nil, messages
// are silently consumed.
//
// Typical usage:
//
//	errorLog := slog.NewLogLogger(logger.Handler(), slog.LevelError)
//	srv := &http.Server{
//	    ErrorLog: guard.WrapErrorLog(errorLog),
//	}
func (g *Guard) WrapErrorLog(fallback *log.Logger) *log.Logger {
	if g == nil {
		return fallback
	}
	return log.New(&tlsErrorWriter{guard: g, fallback: fallback}, "", 0)
}

const tlsHandshakeMarker = "http: TLS handshake error from "

type tlsErrorWriter struct {
	guard    *Guard
	fallback *log.Logger
}

func (w *tlsErrorWriter) Write(p []byte) (int, error) {
	msg := string(bytes.TrimRight(p, "\n"))

	if idx := strings.Index(msg, tlsHandshakeMarker); idx >= 0 {
		rest := msg[idx+len(tlsHandshakeMarker):]
		if colonIdx := strings.Index(rest, ": "); colonIdx >= 0 {
			hostPort := rest[:colonIdx]
			if ip, _, err := net.SplitHostPort(hostPort); err == nil {
				w.guard.RecordFailure(ip, "https")
			}
		}
	}

	if w.fallback != nil {
		w.fallback.Printf("%s", msg)
	} else if w.guard.logger != nil {
		w.guard.logger.Printf("%s", msg)
	}
	return len(p), nil
}
