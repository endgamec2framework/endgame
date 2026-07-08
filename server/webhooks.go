package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FireWebhooks sends a notification to all enabled webhooks that subscribe to the given event.
// Called asynchronously — never blocks the caller.
func (s *Server) FireWebhooks(event, message string) {
	hooks, err := s.db.ListWebhooks()
	if err != nil {
		return
	}
	for _, h := range hooks {
		if !h.Enabled {
			continue
		}
		if !strings.Contains(h.Events, event) {
			continue
		}
		go s.sendWebhook(h, event, message)
	}
}

func (s *Server) sendWebhook(h *WebhookConfig, event, message string) {
	var payload []byte
	switch h.Type {
	case "discord":
		payload, _ = json.Marshal(map[string]string{
			"content": fmt.Sprintf("**[ENDGAME C2]** `%s` — %s", event, message),
		})
	case "slack":
		payload, _ = json.Marshal(map[string]string{
			"text": fmt.Sprintf("[ENDGAME C2] `%s` — %s", event, message),
		})
	case "telegram":
		// URL must be the full sendMessage endpoint, e.g.
		// https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}
		payload, _ = json.Marshal(map[string]string{
			"text": fmt.Sprintf("[ENDGAME C2] %s — %s", event, message),
		})
	default: // generic
		payload, _ = json.Marshal(map[string]string{
			"event":   event,
			"message": message,
		})
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		s.printf("[webhook] %s send error: %v\n", h.Name, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.printf("[webhook] %s returned HTTP %d\n", h.Name, resp.StatusCode)
	}
}
