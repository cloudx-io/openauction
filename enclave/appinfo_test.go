package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/peterldowns/testy/assert"
)

// testServer builds a server with a worker pool of the given size, bypassing
// Start (which needs a real vsock listener).
func testServer(t *testing.T, maxWorkers int) *EnclaveServer {
	t.Helper()
	s := NewEnclaveServer(5000)
	s.workers = make(chan struct{}, maxWorkers)
	return s
}

func TestAppInfo_ReportsPoolOccupancyAndCounters(t *testing.T) {
	s := testServer(t, 4)
	s.workers <- struct{}{}
	s.workers <- struct{}{}
	s.connsAccepted.Add(7)
	s.connsRejected.Add(2)

	info := s.appInfo()

	assert.Equal(t, 4, info.WorkersMax)
	assert.Equal(t, 2, info.WorkersInUse)
	assert.Equal(t, uint64(7), info.ConnsAcceptedTotal)
	assert.Equal(t, uint64(2), info.ConnsRejectedTotal)
}

func TestAppInfo_ReportsRuntimeInternals(t *testing.T) {
	s := testServer(t, 1)

	info := s.appInfo()

	assert.True(t, info.Goroutines >= 1)
	assert.True(t, info.HeapAllocBytes > 0)
	// A short test binary may never GC; once it has, the cumulative pause time
	// must be reported alongside the count.
	if info.GCNum > 0 {
		assert.True(t, info.GCPauseTotalMillis > 0)
	}
}

func TestAppInfo_UptimeMeasuredFromStartTime(t *testing.T) {
	s := testServer(t, 1)
	s.startTime = time.Now().Add(-90 * time.Second)

	assert.True(t, s.appInfo().UptimeSeconds >= 90)
}

// A server built without NewEnclaveServer has a zero startTime; uptime must read
// 0 rather than the seconds elapsed since the zero time.
func TestAppInfo_ZeroStartTimeReportsZeroUptime(t *testing.T) {
	s := &EnclaveServer{}

	assert.Equal(t, 0.0, s.appInfo().UptimeSeconds)
}

// appInfo is reachable before Start sizes the pool, so a nil channel must report
// an empty pool instead of panicking.
func TestAppInfo_NilWorkerPoolReportsZeroes(t *testing.T) {
	s := NewEnclaveServer(5000)

	info := s.appInfo()

	assert.Equal(t, 0, info.WorkersMax)
	assert.Equal(t, 0, info.WorkersInUse)
}

// pongPayload mirrors how the host-side bridge decodes a pong: the blocks it
// reads, and nothing else.
type pongPayload struct {
	Type   string      `json:"type"`
	System *SystemInfo `json:"system"`
	App    *AppInfo    `json:"app"`
}

// The pong payload is the wire contract the host-side bridge parses, so assert
// on the serialized JSON rather than the in-process struct.
func TestPingResponse_CarriesSystemAndAppBlocks(t *testing.T) {
	s := testServer(t, 8)
	s.connsAccepted.Add(3)

	raw, err := json.Marshal(s.pingResponse())
	assert.NoError(t, err)

	var pong pongPayload
	assert.NoError(t, json.Unmarshal(raw, &pong))

	assert.Equal(t, "pong", pong.Type)
	assert.NotNil(t, pong.App)
	assert.Equal(t, 8, pong.App.WorkersMax)
	assert.Equal(t, uint64(3), pong.App.ConnsAcceptedTotal)
	// system is collected from /proc and may be absent off Linux; when present it
	// must still carry the fields the bridge reads.
	if pong.System != nil {
		assert.True(t, pong.System.MemTotalBytes > 0)
	}
}

func TestDispatch_RejectsAndClosesWhenPoolFull(t *testing.T) {
	s := testServer(t, 1)
	s.workers <- struct{}{}

	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })

	s.dispatch(conn)

	assert.Equal(t, uint64(1), s.connsRejected.Load())
	// A rejected connection is closed before dispatch returns, so any further
	// write must fail.
	_, err := conn.Write([]byte("x"))
	assert.Error(t, err)
}

func TestDispatch_AcceptsWhenPoolHasRoom(t *testing.T) {
	s := testServer(t, 1)

	conn, peer := net.Pipe()
	// Closing the peer ends the worker's read-until-EOF so it does not outlive
	// the test.
	assert.NoError(t, peer.Close())

	s.dispatch(conn)

	assert.Equal(t, uint64(0), s.connsRejected.Load())
}

func TestRoundTenths(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1.24, 1.2},
		{1.25, 1.3},
		{90.06, 90.1},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, roundTenths(tt.in))
	}
}
