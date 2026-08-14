package main

import (
	"math"
	"runtime"
	"time"
)

// AppInfo reports application internals on the ping response, alongside
// SystemInfo's /proc view of the enclave VM. A degrading or wedged server shows
// up here first -- goroutines growing without bound, GC pause time climbing, the
// worker pool saturating, or an accept loop that has stopped advancing -- while
// /proc CPU and memory can read entirely normal.
//
// Counters are cumulative for the life of the process, not deltas: the host-side
// collector is stateless and rates are derived where they are queried. An
// enclave restart therefore resets them to zero.
type AppInfo struct {
	UptimeSeconds float64 `json:"uptime_s"`

	Goroutines         int     `json:"goroutines"`
	GCNum              uint32  `json:"gc_num"`
	GCPauseTotalMillis float64 `json:"gc_pause_total_ms"`
	HeapAllocBytes     uint64  `json:"heap_alloc_bytes"`

	ConnsAcceptedTotal uint64 `json:"conns_accepted_total"`
	ConnsRejectedTotal uint64 `json:"conns_rejected_total"`

	WorkersInUse int `json:"workers_in_use"`
	WorkersMax   int `json:"workers_max"`
}

// appInfo snapshots the current application internals. Cheap enough for the ping
// path, which every liveness probe and metrics tick traverses: atomic loads, two
// channel length reads, and one runtime.ReadMemStats (a brief stop-the-world,
// microseconds at this heap size and far cheaper than the CPU sample SystemInfo
// already takes on the same request).
//
// WorkersInUse counts the request being served right now, so on the ping path it
// never reads zero -- a fully idle server reports 1.
func (s *EnclaveServer) appInfo() *AppInfo {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Read rejected before accepted. The accept loop increments accepted first
	// and only then, for a rejected connection, rejected; reading them in the
	// opposite order keeps the reported accepted >= rejected even when a
	// rejection lands between the two loads.
	rejected := s.connsRejected.Load()
	accepted := s.connsAccepted.Load()

	return &AppInfo{
		UptimeSeconds:      s.uptimeSeconds(),
		Goroutines:         runtime.NumGoroutine(),
		GCNum:              mem.NumGC,
		GCPauseTotalMillis: roundTenths(float64(mem.PauseTotalNs) / float64(time.Millisecond)),
		HeapAllocBytes:     mem.HeapAlloc,
		ConnsAcceptedTotal: accepted,
		ConnsRejectedTotal: rejected,
		WorkersInUse:       len(s.workers),
		WorkersMax:         cap(s.workers),
	}
}

// uptimeSeconds reports how long the server has been running. A zero startTime
// means the server was built without NewEnclaveServer, so report 0 rather than
// seconds since the zero time.
func (s *EnclaveServer) uptimeSeconds() float64 {
	if s.startTime.IsZero() {
		return 0
	}
	return roundTenths(time.Since(s.startTime).Seconds())
}

func roundTenths(v float64) float64 {
	return math.Round(v*10) / 10
}
