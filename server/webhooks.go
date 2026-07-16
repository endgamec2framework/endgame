package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fireReactions queues all enabled reactions for the given event against the given agent.
func (s *Server) fireReactions(event, agentID string) {
	reactions, err := s.db.EnabledReactionsForEvent(event)
	if err != nil || len(reactions) == 0 {
		return
	}
	for _, r := range reactions {
		if _, err := s.db.QueueTask(agentID, r.TaskType, r.TaskArgs, nil, "reaction:"+r.Name); err != nil {
			s.printf("[reaction] queue %s → %s: %v\n", r.Name, agentID[:8], err)
		} else {
			s.printf("[reaction] queued %s (%s %s) → %s\n", r.Name, r.TaskType, r.TaskArgs, agentID[:8])
		}
	}
}

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

// apiTelegramUpdates proxies a getUpdates call to Telegram and returns the
// first chat_id found, so the GUI can auto-detect it without exposing the
// token to a third-party service.
// GET /api/telegram/updates?token=<BOT_TOKEN>
func (s *Server) apiTelegramUpdates(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		jsonErr(w, "token required", http.StatusBadRequest)
		return
	}

	// Use allowed_updates=[] and a short timeout to get any pending update.
	// Also try with offset=0 to reset the webhook conflict if any.
	tgURL := "https://api.telegram.org/bot" + token + "/getUpdates?limit=10&timeout=3"
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(tgURL)
	if err != nil {
		jsonErr(w, "telegram unreachable: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Generic parse — pull any chat.id out of the raw JSON to handle all
	// update types (message, edited_message, channel_post, callback_query, etc.)
	var raw struct {
		OK          bool            `json:"ok"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Result      []json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		jsonErr(w, "parse error: "+err.Error(), 502)
		return
	}
	if !raw.OK {
		jsonErr(w, fmt.Sprintf("telegram: %s", raw.Description), 502)
		return
	}

	// Walk every update and find the first chat.id anywhere in the tree
	type chatHolder struct {
		Chat *struct{ ID int64 `json:"id"` } `json:"chat"`
	}
	type anyUpdate struct {
		Message         *chatHolder `json:"message"`
		EditedMessage   *chatHolder `json:"edited_message"`
		ChannelPost     *chatHolder `json:"channel_post"`
		CallbackQuery   *struct {
			Message *chatHolder `json:"message"`
		} `json:"callback_query"`
		MyChatMember *struct {
			Chat struct{ ID int64 `json:"id"` } `json:"chat"`
		} `json:"my_chat_member"`
	}
	var chatID int64
	for _, raw := range raw.Result {
		var u anyUpdate
		if json.Unmarshal(raw, &u) != nil {
			continue
		}
		switch {
		case u.Message != nil && u.Message.Chat != nil:
			chatID = u.Message.Chat.ID
		case u.EditedMessage != nil && u.EditedMessage.Chat != nil:
			chatID = u.EditedMessage.Chat.ID
		case u.ChannelPost != nil && u.ChannelPost.Chat != nil:
			chatID = u.ChannelPost.Chat.ID
		case u.CallbackQuery != nil && u.CallbackQuery.Message != nil && u.CallbackQuery.Message.Chat != nil:
			chatID = u.CallbackQuery.Message.Chat.ID
		case u.MyChatMember != nil:
			chatID = u.MyChatMember.Chat.ID
		}
		if chatID != 0 {
			break
		}
	}

	if chatID == 0 {
		jsonErr(w, "no updates found — open Telegram, send any message to your bot, then click Auto-detect again", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"chat_id": chatID})
}
