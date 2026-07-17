package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	HTTPPort     int
	MTLSPort     int
	OperatorPort int
	DBPath       string
	CertsDir     string
	DataDir      string
}

type Job struct {
	ID        int       `json:"id"`
	Protocol  string    `json:"protocol"` // "HTTP" | "mTLS"
	Port      int       `json:"port"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"` // "running" | "stopped"
}

type pendingPivot struct {
	parentID string
	expires  time.Time
}

// meshPeer represents an agent that is actively running a pivot listener and
// can relay C2 traffic for other agents that cannot reach the teamserver directly.
type meshPeer struct {
	AgentID string
	Addr    string    // "ip:port" reachable by other agents on the same network
	Proto   string    // "http" or "tcp"
	Updated time.Time
}

type Server struct {
	cfg     Config
	db      *DB
	ca      *CertBundle
	chat    *ChatStore
	online  *onlineTracker
	mu      sync.Mutex
	printBuf chan string
	jobs    []*Job
	jobSrvs map[int]*http.Server
	tcpLns  map[int]net.Listener
	dnsSrvs map[int]*dns.Server
	nextJob int
	mux     *http.ServeMux

	pivotMu      sync.Mutex
	pendingPivots map[string]pendingPivot // targetIP → pending

	meshMu    sync.RWMutex
	meshPeers map[string]meshPeer // agentID → peer info
}

// registerPendingPivot records that agentID is about to deploy a child to targetIP.
// The association is valid for 5 minutes.
func (s *Server) registerPendingPivot(targetIP, parentAgentID string) {
	s.pivotMu.Lock()
	defer s.pivotMu.Unlock()
	if s.pendingPivots == nil {
		s.pendingPivots = make(map[string]pendingPivot)
	}
	s.pendingPivots[targetIP] = pendingPivot{
		parentID: parentAgentID,
		expires:  time.Now().Add(5 * time.Minute),
	}
}

// claimPendingPivot returns the parent agent ID if ip has a valid pending pivot entry,
// consuming the entry. Returns "" if none found or expired.
func (s *Server) claimPendingPivot(ip string) string {
	s.pivotMu.Lock()
	defer s.pivotMu.Unlock()
	if s.pendingPivots == nil {
		return ""
	}
	p, ok := s.pendingPivots[ip]
	if !ok {
		return ""
	}
	delete(s.pendingPivots, ip)
	if time.Now().After(p.expires) {
		return ""
	}
	return p.parentID
}

// registerMeshPeer records an agent as an active relay peer.
func (s *Server) registerMeshPeer(agentID, addr, proto string) {
	s.meshMu.Lock()
	defer s.meshMu.Unlock()
	if s.meshPeers == nil {
		s.meshPeers = make(map[string]meshPeer)
	}
	s.meshPeers[agentID] = meshPeer{AgentID: agentID, Addr: addr, Proto: proto, Updated: time.Now()}
}

// unregisterMeshPeer removes an agent from the mesh peer list.
func (s *Server) unregisterMeshPeer(agentID string) {
	s.meshMu.Lock()
	defer s.meshMu.Unlock()
	delete(s.meshPeers, agentID)
}

// getMeshPeers returns up to 8 active peers, excluding the requesting agent itself.
// Stale peers (no update in 30 min) are pruned on each call.
func (s *Server) getMeshPeers(excludeAgentID string) []meshPeer {
	s.meshMu.Lock()
	defer s.meshMu.Unlock()
	cutoff := time.Now().Add(-30 * time.Minute)
	var out []meshPeer
	for id, p := range s.meshPeers {
		if p.Updated.Before(cutoff) {
			delete(s.meshPeers, id)
			continue
		}
		if id == excludeAgentID {
			continue
		}
		out = append(out, p)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func New(cfg Config) (*Server, error) {
	os.MkdirAll(cfg.CertsDir, 0700)
	os.MkdirAll(cfg.DataDir, 0700)
	os.MkdirAll(filepath.Join(cfg.DataDir, "uploads"), 0700)
	os.MkdirAll(filepath.Join(cfg.DataDir, "downloads"), 0700)

	db, err := NewDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	ca, err := EnsureCA(cfg.CertsDir)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	cs := newChatStore()
	return &Server{
		cfg:      cfg,
		db:       db,
		ca:       ca,
		chat:     cs,
		online:   newOnlineTracker(cs),
		printBuf: make(chan string, 256),
		jobSrvs:  make(map[int]*http.Server),
		tcpLns:   make(map[int]net.Listener),
		dnsSrvs:  make(map[int]*dns.Server),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.mux = mux
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/beacon/", s.handleBeacon)
	mux.HandleFunc("/result/", s.handleResult)
	mux.HandleFunc("/upload/", s.handleUpload)
	mux.HandleFunc("/dl/", s.handleDownload)
	mux.HandleFunc("/stage/", s.handleStage)
	mux.HandleFunc("/dns-query", s.agentDoHQuery)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	errCh := make(chan error, 2)

	// Plain HTTP listener
	httpJob := s.addJob("HTTP", s.cfg.HTTPPort)
	httpSrv := &http.Server{Addr: fmt.Sprintf(":%d", s.cfg.HTTPPort), Handler: mux}
	s.mu.Lock()
	s.jobSrvs[httpJob.ID] = httpSrv
	s.mu.Unlock()
	go func() {
		s.printf("[*] HTTP listener on :%d  (job #%d)\n", s.cfg.HTTPPort, httpJob.ID)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			s.stopJob(httpJob.ID)
			errCh <- err
		}
	}()

	// mTLS listener
	serverCert, err := s.ca.SignServerCert(s.cfg.CertsDir, localIPs())
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(s.ca.CACertPEM)

	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caPool,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,    // hybrid PQ: X25519 + ML-KEM-768 (NIST FIPS 203)
			tls.X25519,            // classical fallback
			tls.CurveP256,
		},
	}
	mtlsSrv := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.cfg.MTLSPort),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}
	mtlsJob := s.addJob("mTLS", s.cfg.MTLSPort)
	s.mu.Lock()
	s.jobSrvs[mtlsJob.ID] = mtlsSrv
	s.mu.Unlock()
	go func() {
		s.printf("[*] mTLS listener on :%d  (job #%d)\n", s.cfg.MTLSPort, mtlsJob.ID)
		ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.cfg.MTLSPort), tlsCfg)
		if err != nil {
			s.stopJob(mtlsJob.ID)
			errCh <- err
			return
		}
		if err := mtlsSrv.Serve(ln); err != http.ErrServerClosed {
			s.stopJob(mtlsJob.ID)
			errCh <- err
		}
	}()

	// Drain print buffer to stdout
	go func() {
		for msg := range s.printBuf {
			fmt.Print(msg)
		}
	}()

	select {
	case <-ctx.Done():
		httpSrv.Shutdown(context.Background())
		mtlsSrv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) printf(format string, args ...any) {
	select {
	case s.printBuf <- fmt.Sprintf(format, args...):
	default:
	}
}

func (s *Server) GetDB() *DB           { return s.db }
func (s *Server) GetCA() *CertBundle   { return s.ca }
func (s *Server) GetCertsDir() string  { return s.cfg.CertsDir }
func (s *Server) GetCfg() Config       { return s.cfg }
func (s *Server) GetMux() http.Handler { return s.mux }

func (s *Server) StopJob(id int) error {
	s.mu.Lock()
	srv  := s.jobSrvs[id]
	ln   := s.tcpLns[id]
	dsrv := s.dnsSrvs[id]
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
		s.mu.Lock()
		delete(s.tcpLns, id)
		s.mu.Unlock()
		s.stopJob(id)
		return nil
	}
	if dsrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dsrv.ShutdownContext(ctx)
		s.mu.Lock()
		delete(s.dnsSrvs, id)
		s.mu.Unlock()
		s.stopJob(id)
		return nil
	}
	if srv == nil {
		return fmt.Errorf("job #%d not found", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	s.stopJob(id)
	return nil
}

func (s *Server) addJob(proto string, port int) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextJob++
	j := &Job{ID: s.nextJob, Protocol: proto, Port: port, StartedAt: time.Now(), Status: "running"}
	s.jobs = append(s.jobs, j)
	return j
}

func (s *Server) stopJob(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.ID == id {
			j.Status = "stopped"
			return
		}
	}
}

func (s *Server) removeJob(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, j := range s.jobs {
		if j.ID == id {
			s.jobs = append(s.jobs[:i], s.jobs[i+1:]...)
			return
		}
	}
}

func (s *Server) GetJobs() []*Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Job, len(s.jobs))
	copy(out, s.jobs)
	return out
}

// StartHTTP starts a new HTTP listener on the given port and registers it as a job.
func (s *Server) StartHTTP(mux http.Handler, port int) int {
	job := s.addJob("HTTP", port)
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()
	go func() {
		s.printf("[*] HTTP listener on :%d  (job #%d)\n", port, job.ID)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			s.stopJob(job.ID)
		}
	}()
	return job.ID
}

// StartMTLS starts a new mTLS listener on the given port and registers it as a job.
func (s *Server) StartMTLS(mux http.Handler, port int) (int, error) {
	serverCert, err := s.ca.SignServerCert(s.cfg.CertsDir, localIPs())
	if err != nil {
		return 0, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(s.ca.CACertPEM)
	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caPool,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,    // hybrid PQ: X25519 + ML-KEM-768 (NIST FIPS 203)
			tls.X25519,            // classical fallback
			tls.CurveP256,
		},
	}
	job := s.addJob("mTLS", port)
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()
	go func() {
		s.printf("[*] mTLS listener on :%d  (job #%d)\n", port, job.ID)
		ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsCfg)
		if err != nil {
			s.stopJob(job.ID)
			return
		}
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			s.stopJob(job.ID)
		}
	}()
	return job.ID, nil
}

// StartHTTPS starts a one-way TLS (HTTPS) listener on the given port.
// Unlike mTLS, no client certificate is required — standard HTTPS only.
func (s *Server) StartHTTPS(mux http.Handler, port int) (int, error) {
	serverCert, err := s.ca.SignServerCert(s.cfg.CertsDir, localIPs())
	if err != nil {
		return 0, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}
	job := s.addJob("HTTPS", port)
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()
	go func() {
		ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsCfg)
		if err != nil {
			s.printf("[-] HTTPS listener :%d failed: %v\n", port, err)
			s.stopJob(job.ID)
			return
		}
		s.printf("[*] HTTPS listener on :%d  (job #%d)\n", port, job.ID)
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			s.printf("[-] HTTPS listener :%d stopped: %v\n", port, err)
			s.stopJob(job.ID)
		}
	}()
	return job.ID, nil
}

// StartTCP starts a raw TCP agent listener and registers it as a job.
func (s *Server) StartTCP(port int) (int, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return 0, fmt.Errorf("tcp listen :%d: %w", port, err)
	}
	job := s.addJob("TCP", port)
	s.mu.Lock()
	s.tcpLns[job.ID] = ln
	s.mu.Unlock()
	s.printf("[*] TCP listener on :%d  (job #%d)\n", port, job.ID)
	go func() {
		defer s.stopJob(job.ID)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleTCPAgent(conn)
		}
	}()
	return job.ID, nil
}

func localIPs() []net.IP {
	ifaces, _ := net.Interfaces()
	var ips []net.IP
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ips = append(ips, ip4)
				}
			}
		}
	}
	return ips
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
