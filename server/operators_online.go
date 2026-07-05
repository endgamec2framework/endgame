package server

import (
	"sync"
	"time"
)

const operatorTimeout = 30 * time.Second

type onlineTracker struct {
	mu       sync.Mutex
	seen     map[string]time.Time // operator CN → last heartbeat
	chat     *ChatStore
}

func newOnlineTracker(chat *ChatStore) *onlineTracker {
	t := &onlineTracker{
		seen: make(map[string]time.Time),
		chat: chat,
	}
	go t.watchLoop()
	return t
}

// Heartbeat registers a ping from an operator. Posts a join message on first contact.
func (t *onlineTracker) Heartbeat(operator string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, known := t.seen[operator]
	t.seen[operator] = time.Now()
	if !known {
		t.chat.Post("sistema", "** "+operator+" se ha conectado **")
	}
}

// Online returns the list of currently active operators.
func (t *onlineTracker) Online() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for op := range t.seen {
		out = append(out, op)
	}
	return out
}

// watchLoop evicts operators that haven't pinged in operatorTimeout and posts a disconnect message.
func (t *onlineTracker) watchLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		for op, last := range t.seen {
			if time.Since(last) > operatorTimeout {
				delete(t.seen, op)
				t.chat.Post("sistema", "** "+op+" se ha desconectado **")
			}
		}
		t.mu.Unlock()
	}
}
