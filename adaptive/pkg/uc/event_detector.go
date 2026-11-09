package uc

import (
	"sync"
	"time"
)

// StrategyEvent is a business IAPP/DAPP strategy observation on the hot path.
type StrategyEvent struct {
	SID        string    `json:"sid"`
	Source     string    `json:"source"` // e.g. "iapp", "dapp", "hot_path"
	IAPP       string    `json:"iapp_strategy"`
	DAPP       string    `json:"dapp_strategy"`
	Phase      string    `json:"phase,omitempty"`
	Role       string    `json:"role,omitempty"`
	ReviewMode string    `json:"review_mode,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// EventDetector is the event-detection module: receives business IAPP/DAPP
// strategy events from the production hot path (or audit taps).
type EventDetector struct {
	mu     sync.Mutex
	last   []StrategyEvent
	maxLog int
}

func NewEventDetector(maxLog int) *EventDetector {
	if maxLog <= 0 {
		maxLog = 128
	}
	return &EventDetector{maxLog: maxLog}
}

// ReceiveIdentityEvent records an IAPP strategy observation.
func (d *EventDetector) ReceiveIdentityEvent(sid, iapp, phase, role, reviewMode string) StrategyEvent {
	ev := StrategyEvent{
		SID: sid, Source: "iapp", IAPP: iapp,
		Phase: phase, Role: role, ReviewMode: reviewMode,
		ObservedAt: time.Now().UTC(),
	}
	d.ingest(ev)
	return ev
}

// ReceiveDataEvent records a DAPP strategy observation.
func (d *EventDetector) ReceiveDataEvent(sid, dapp, phase, role, reviewMode string) StrategyEvent {
	ev := StrategyEvent{
		SID: sid, Source: "dapp", DAPP: dapp,
		Phase: phase, Role: role, ReviewMode: reviewMode,
		ObservedAt: time.Now().UTC(),
	}
	d.ingest(ev)
	return ev
}

// ReceiveCombinedEvent records a joint IAPP+DAPP observation from the hot path.
func (d *EventDetector) ReceiveCombinedEvent(sid, iapp, dapp, phase, role, reviewMode string) StrategyEvent {
	ev := StrategyEvent{
		SID: sid, Source: "hot_path", IAPP: iapp, DAPP: dapp,
		Phase: phase, Role: role, ReviewMode: reviewMode,
		ObservedAt: time.Now().UTC(),
	}
	d.ingest(ev)
	return ev
}

func (d *EventDetector) ingest(ev StrategyEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.last = append(d.last, ev)
	if len(d.last) > d.maxLog {
		d.last = d.last[len(d.last)-d.maxLog:]
	}
}

// Recent returns a copy of the latest events (newest last).
func (d *EventDetector) Recent() []StrategyEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]StrategyEvent, len(d.last))
	copy(out, d.last)
	return out
}
