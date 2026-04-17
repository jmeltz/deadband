package discover

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Schedule defines a recurring discovery scan.
type Schedule struct {
	ID        string     `json:"id"`
	CIDR      string     `json:"cidr"`
	Mode      string     `json:"mode"`
	Interval  string     `json:"interval"` // 1h, 6h, 24h, weekly
	AutoCheck bool       `json:"auto_check"`
	Enabled   bool       `json:"enabled"`
	LastRun   *time.Time `json:"last_run,omitempty"`
	NextRun   *time.Time `json:"next_run,omitempty"`
}

// ScheduleStore persists schedules to disk.
type ScheduleStore struct {
	mu        sync.Mutex
	path      string
	Version   int        `json:"version"`
	Schedules []Schedule `json:"schedules"`
}

// DefaultScheduleStorePath returns ~/.deadband/schedules.json.
func DefaultScheduleStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "schedules.json"
	}
	return filepath.Join(home, ".deadband", "schedules.json")
}

// LoadScheduleStore loads from disk or returns an empty store.
func LoadScheduleStore(path string) *ScheduleStore {
	s := &ScheduleStore{path: path, Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] schedule store %s: parse failed, starting empty: %v", path, err)
		return &ScheduleStore{path: path, Version: 1}
	}
	s.path = path
	return s
}

// Save writes the store to disk.
func (s *ScheduleStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// Upsert creates or updates a schedule. Returns the updated schedule.
func (s *ScheduleStore) Upsert(sched Schedule) Schedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Schedules {
		if s.Schedules[i].ID == sched.ID {
			s.Schedules[i] = sched
			return sched
		}
	}
	s.Schedules = append(s.Schedules, sched)
	return sched
}

// Delete removes a schedule by ID. Returns false if not found.
func (s *ScheduleStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Schedules {
		if s.Schedules[i].ID == id {
			s.Schedules = append(s.Schedules[:i], s.Schedules[i+1:]...)
			return true
		}
	}
	return false
}

// Get returns a schedule by ID.
func (s *ScheduleStore) Get(id string) *Schedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Schedules {
		if s.Schedules[i].ID == id {
			return &s.Schedules[i]
		}
	}
	return nil
}

// List returns all schedules.
func (s *ScheduleStore) List() []Schedule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Schedule, len(s.Schedules))
	copy(out, s.Schedules)
	return out
}

// ParseInterval converts an interval string to a duration.
func ParseInterval(s string) time.Duration {
	switch s {
	case "1h":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		d, err := time.ParseDuration(s)
		if err != nil {
			return 24 * time.Hour
		}
		return d
	}
}

// Scheduler runs scheduled discovery scans.
type Scheduler struct {
	store    *ScheduleStore
	mu       sync.Mutex
	timers   map[string]*time.Timer
	runFunc  func(sched Schedule) // called when a schedule fires
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewScheduler creates a scheduler.
func NewScheduler(store *ScheduleStore, runFunc func(Schedule)) *Scheduler {
	return &Scheduler{
		store:   store,
		timers:  make(map[string]*time.Timer),
		runFunc: runFunc,
		stopCh:  make(chan struct{}),
	}
}

// stopped reports whether Stop has been called.
func (sc *Scheduler) stopped() bool {
	select {
	case <-sc.stopCh:
		return true
	default:
		return false
	}
}

// Start initializes timers for all enabled schedules.
func (sc *Scheduler) Start() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, sched := range sc.store.List() {
		if sched.Enabled {
			sc.scheduleNext(sched)
		}
	}
}

// Stop cancels all timers. Safe to call more than once.
func (sc *Scheduler) Stop() {
	sc.stopOnce.Do(func() { close(sc.stopCh) })
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for id, t := range sc.timers {
		t.Stop()
		delete(sc.timers, id)
	}
}

// Reschedule updates or starts the timer for a schedule.
func (sc *Scheduler) Reschedule(sched Schedule) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if t, ok := sc.timers[sched.ID]; ok {
		t.Stop()
		delete(sc.timers, sched.ID)
	}
	if sched.Enabled {
		sc.scheduleNext(sched)
	}
}

// Cancel stops the timer for a schedule.
func (sc *Scheduler) Cancel(id string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if t, ok := sc.timers[id]; ok {
		t.Stop()
		delete(sc.timers, id)
	}
}

func (sc *Scheduler) scheduleNext(sched Schedule) {
	if sc.stopped() {
		return
	}
	interval := ParseInterval(sched.Interval)
	var delay time.Duration

	if sched.NextRun != nil && sched.NextRun.After(time.Now()) {
		delay = time.Until(*sched.NextRun)
	} else {
		delay = interval
	}

	sc.timers[sched.ID] = time.AfterFunc(delay, func() {
		if sc.stopped() {
			return
		}

		sc.runFunc(sched)

		// Update last/next run
		now := time.Now().UTC()
		next := now.Add(interval)
		sched.LastRun = &now
		sched.NextRun = &next
		sc.store.Upsert(sched)
		sc.store.Save()

		// Re-schedule
		sc.mu.Lock()
		sc.scheduleNext(sched)
		sc.mu.Unlock()
	})
}
