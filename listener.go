package ipguard

import (
	"net"
)

type guardedListener struct {
	net.Listener
	guard     *Guard
	transport string
}

func (gl *guardedListener) Accept() (net.Conn, error) {
	for {
		conn, err := gl.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return conn, nil
		}
		if blocked, reason := gl.guard.IsBlocked(ip); blocked {
			gl.guard.logBlocked(ip, reason, gl.transport)
			conn.Close()
			continue
		}
		return conn, nil
	}
}
