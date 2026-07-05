package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	// Accept any origin — access is restricted by network (loopback only)
	CheckOrigin: func(r *http.Request) bool { return true },
}

// StartWSTunnel starts a plain-HTTP WebSocket bridge on 127.0.0.1:<port>.
// Each WebSocket connection is piped byte-for-byte to the operator mTLS port
// (127.0.0.1:OperatorPort). Cloudflare Tunnel / ngrok points at this port;
// the inner mTLS handshake travels transparently through the WebSocket frames.
//
// Flow:
//
//	client → WSS (Cloudflare TLS) → CF edge → plain WS → this bridge → TCP → operator mTLS
func (s *Server) StartWSTunnel(port int) int {
	operatorAddr := fmt.Sprintf("127.0.0.1:%d", s.cfg.OperatorPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		tc, err := net.Dial("tcp", operatorAddr)
		if err != nil {
			ws.Close()
			return
		}
		pipeWSToTCP(ws, tc)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	job := s.addJob("wstunnel", port)
	srv := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()

	go func() {
		s.printf("[*] WS tunnel  127.0.0.1:%d/ws → operator :%d  (job #%d)\n",
			port, s.cfg.OperatorPort, job.ID)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			s.stopJob(job.ID)
		}
	}()
	return job.ID
}

// pipeWSToTCP bridges a WebSocket connection to a plain TCP connection.
// Each WS binary frame payload is written verbatim to TCP, and TCP reads
// are sent as binary frames. Closes both sides when either half errors.
func pipeWSToTCP(ws *websocket.Conn, tc net.Conn) {
	errc := make(chan error, 2)

	// WS → TCP
	go func() {
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				errc <- err
				return
			}
			if _, err := tc.Write(msg); err != nil {
				errc <- err
				return
			}
		}
	}()

	// TCP → WS
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := tc.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
	ws.Close()
	tc.Close()
}
