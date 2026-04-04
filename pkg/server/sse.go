package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jmeltz/deadband/pkg/discover"
	"github.com/jmeltz/deadband/pkg/inventory"
	"github.com/jmeltz/deadband/pkg/updater"
)

func newJobID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Discovery job management ---

type jobStatus string

const (
	jobRunning  jobStatus = "running"
	jobComplete jobStatus = "complete"
	jobError    jobStatus = "error"
)

type discoverJob struct {
	ID       string              `json:"job_id"`
	Status   jobStatus           `json:"status"`
	Error    string              `json:"error,omitempty"`
	Devices  []inventory.Device  `json:"devices,omitempty"`
	Results  *checkResponse      `json:"check_results,omitempty"`
	Progress []string            `json:"progress,omitempty"`

	mu       sync.Mutex
	subs     []chan string
}

func (j *discoverJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Progress = append(j.Progress, msg)
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *discoverJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	// Send buffered progress
	for _, msg := range j.Progress {
		ch <- msg
	}
	j.subs = append(j.subs, ch)
	return ch
}

func (j *discoverJob) complete(devices []inventory.Device, results *checkResponse, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Devices = devices
	j.Results = results
	if errMsg != "" {
		j.Status = jobError
		j.Error = errMsg
	} else {
		j.Status = jobComplete
	}
	// Signal completion to all subscribers
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

var (
	discoverJobs   sync.Map
	discoverMu     sync.Mutex // Limits to one concurrent discovery
)

// --- Update job management ---

type updateJob struct {
	mu       sync.Mutex
	subs     []chan string
	done     bool
}

func (j *updateJob) addProgress(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, ch := range j.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (j *updateJob) finish() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	for _, ch := range j.subs {
		close(ch)
	}
	j.subs = nil
}

func (j *updateJob) subscribe() chan string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch := make(chan string, 64)
	j.subs = append(j.subs, ch)
	return ch
}

var (
	activeUpdate   *updateJob
	activeUpdateMu sync.Mutex
)

// startBackgroundUpdate kicks off an advisory DB update when the server starts with no data.
func (s *Server) startBackgroundUpdate() {
	activeUpdateMu.Lock()
	job := &updateJob{}
	activeUpdate = job
	activeUpdateMu.Unlock()

	go func() {
		defer job.finish()
		log.Printf("[deadband] Starting automatic advisory database update...")

		opts := updater.UpdateOpts{
			DBPath: s.dbPath,
			Progress: func(msg string) {
				log.Printf("[deadband] %s", msg)
				job.addProgress(msg)
			},
		}

		_, err := updater.Update(opts)
		if err != nil {
			log.Printf("[deadband] Auto-update error: %v", err)
			job.addProgress(fmt.Sprintf("Error: %v", err))
			return
		}

		if err := s.reloadDB(); err != nil {
			log.Printf("[deadband] Reload error: %v", err)
			return
		}

		log.Printf("[deadband] Auto-update complete. %s", s.db.Stats())
		job.addProgress(fmt.Sprintf("Update complete. %s", s.db.Stats()))
	}()
}

// --- Discovery handlers ---

type discoverRequest struct {
	CIDR        string `json:"cidr"`
	Mode        string `json:"mode"`
	TimeoutMS   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
	AutoCheck   bool   `json:"auto_check"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}
	if req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "cidr is required"})
		return
	}

	if !discoverMu.TryLock() {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "a discovery scan is already running"})
		return
	}

	jobID := newJobID()
	job := &discoverJob{ID: jobID, Status: jobRunning}
	discoverJobs.Store(jobID, job)

	timeout := 2 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	concurrency := 50
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}
	mode := discover.ModeAuto
	switch req.Mode {
	case "cip":
		mode = discover.ModeCIP
	case "s7":
		mode = discover.ModeS7
	case "modbus":
		mode = discover.ModeModbusTCP
	case "http":
		mode = discover.ModeLegacyHTTP
	}

	go func() {
		defer discoverMu.Unlock()

		opts := discover.Opts{
			CIDR:        req.CIDR,
			Timeout:     timeout,
			HTTPTimeout: 5 * time.Second,
			Concurrency: concurrency,
			Mode:        mode,
			Progress: func(msg string) {
				job.addProgress(msg)
			},
		}

		devices, err := discover.Run(opts)
		if err != nil {
			job.complete(nil, nil, err.Error())
			return
		}

		job.addProgress(fmt.Sprintf("Discovered %d devices", len(devices)))

		var results *checkResponse
		if req.AutoCheck && len(devices) > 0 {
			job.addProgress("Running vulnerability check on discovered devices...")
			resp := s.runCheck(devices, "low", 0, "")
			results = &resp
			job.addProgress(fmt.Sprintf("Check complete: %d vulnerable, %d potential, %d ok",
				resp.Summary.Vulnerable, resp.Summary.Potential, resp.Summary.OK))
		}

		job.complete(devices, results, "")
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID, "status": "running"})
}

func (s *Server) handleDiscoverStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := discoverJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, val.(*discoverJob))
}

func (s *Server) handleDiscoverEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	val, ok := discoverJobs.Load(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "job not found"})
		return
	}
	job := val.(*discoverJob)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "streaming not supported"})
		return
	}

	ch := job.subscribe()
	for msg := range ch {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		flusher.Flush()
	}

	// Send final status
	data, _ := json.Marshal(map[string]any{
		"type":    "complete",
		"status":  job.Status,
		"devices": job.Devices,
		"results": job.Results,
		"error":   job.Error,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// --- Update handlers ---

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	activeUpdateMu.Lock()
	if activeUpdate != nil && !activeUpdate.done {
		activeUpdateMu.Unlock()
		writeJSON(w, http.StatusConflict, errorResponse{Error: "an update is already running"})
		return
	}
	job := &updateJob{}
	activeUpdate = job
	activeUpdateMu.Unlock()

	go func() {
		defer job.finish()

		opts := updater.UpdateOpts{
			DBPath: s.dbPath,
			Since:  req.Since,
			Source: req.Source,
			Progress: func(msg string) {
				job.addProgress(msg)
			},
		}

		_, err := updater.Update(opts)
		if err != nil {
			job.addProgress(fmt.Sprintf("Error: %v", err))
			log.Printf("[deadband] Update error: %v", err)
			return
		}

		if err := s.reloadDB(); err != nil {
			job.addProgress(fmt.Sprintf("Warning: failed to reload DB: %v", err))
			log.Printf("[deadband] Reload error: %v", err)
			return
		}

		job.addProgress(fmt.Sprintf("Update complete. %s", s.db.Stats()))
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "updating"})
}

func (s *Server) handleUpdateEvents(w http.ResponseWriter, r *http.Request) {
	activeUpdateMu.Lock()
	job := activeUpdate
	activeUpdateMu.Unlock()

	if job == nil {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no update in progress"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "streaming not supported"})
		return
	}

	ch := job.subscribe()
	for msg := range ch {
		fmt.Fprintf(w, "data: %s\n\n", msg)
		flusher.Flush()
	}

	fmt.Fprintf(w, "data: {\"type\":\"complete\"}\n\n")
	flusher.Flush()
}

