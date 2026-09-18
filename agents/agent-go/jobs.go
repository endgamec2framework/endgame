package agent

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type bgJob struct {
	id        int64
	taskID    int64
	name      string
	startedAt time.Time
}

var (
	bgJobMu      sync.Mutex
	bgJobSeq     int64
	bgJobRegistry = map[int64]*bgJob{}
)

// jobAdd registers a new background job and returns its ID.
func jobAdd(taskID int64, name string) int64 {
	bgJobMu.Lock()
	defer bgJobMu.Unlock()
	bgJobSeq++
	bgJobRegistry[bgJobSeq] = &bgJob{
		id:        bgJobSeq,
		taskID:    taskID,
		name:      name,
		startedAt: time.Now(),
	}
	return bgJobSeq
}

// jobDone removes a completed background job.
func jobDone(id int64) {
	bgJobMu.Lock()
	delete(bgJobRegistry, id)
	bgJobMu.Unlock()
}

// jobList returns a formatted table of running background jobs.
func jobList() string {
	bgJobMu.Lock()
	defer bgJobMu.Unlock()
	if len(bgJobRegistry) == 0 {
		return "no background jobs running"
	}
	lines := make([]string, 0, len(bgJobRegistry))
	for _, j := range bgJobRegistry {
		lines = append(lines, fmt.Sprintf("[%d]  %-22s  running %s  (task %d)",
			j.id, j.name, time.Since(j.startedAt).Truncate(time.Second), j.taskID))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
