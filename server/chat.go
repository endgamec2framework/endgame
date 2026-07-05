package server

import (
	"sync"
	"time"
)

type ChatMessage struct {
	ID        int64     `json:"id"`
	Operator  string    `json:"operator"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

type ChatStore struct {
	mu       sync.RWMutex
	messages []*ChatMessage
	nextID   int64
	maxSize  int
}

func newChatStore() *ChatStore {
	return &ChatStore{maxSize: 500}
}

func (cs *ChatStore) Post(operator, text string) *ChatMessage {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.nextID++
	msg := &ChatMessage{
		ID:        cs.nextID,
		Operator:  operator,
		Text:      text,
		Timestamp: time.Now(),
	}
	cs.messages = append(cs.messages, msg)
	// Trim circular buffer
	if len(cs.messages) > cs.maxSize {
		cs.messages = cs.messages[len(cs.messages)-cs.maxSize:]
	}
	return msg
}

// Since returns all messages with ID > sinceID.
func (cs *ChatStore) Since(sinceID int64) []*ChatMessage {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var out []*ChatMessage
	for _, m := range cs.messages {
		if m.ID > sinceID {
			out = append(out, m)
		}
	}
	return out
}

func (cs *ChatStore) LastID() int64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if len(cs.messages) == 0 {
		return 0
	}
	return cs.messages[len(cs.messages)-1].ID
}
