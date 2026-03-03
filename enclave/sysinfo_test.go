package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peterldowns/testy/assert"
)

func TestParseMemInfoLine(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal uint64
		wantOK  bool
	}{
		{"MemTotal:       16384000 kB", "MemTotal", 16384000, true},
		{"MemAvailable:    8192000 kB", "MemAvailable", 8192000, true},
		{"MemFree:         4096000 kB", "MemFree", 4096000, true},
		{"Buffers:          512000 kB", "Buffers", 512000, true},
		{"Cached:          2048000 kB", "Cached", 2048000, true},
		{"bogus line", "", 0, false},
		{"NoValue:", "", 0, false},
	}

	for _, tt := range tests {
		key, val, ok := parseMemInfoLine(tt.line)
		assert.Equal(t, tt.wantOK, ok)
		if ok {
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantVal, val)
		}
	}
}

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	err := os.WriteFile(path, []byte(content), 0o644)
	assert.NoError(t, err)
	return path
}

func TestReadMemInfo(t *testing.T) {
	content := `MemTotal:       16384000 kB
MemFree:         4096000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
`
	path := writeFixture(t, "meminfo", content)

	mem, err := readMemInfo(path)
	assert.NoError(t, err)

	assert.Equal(t, uint64(16384000*1024), mem.totalBytes)
	assert.Equal(t, uint64((16384000-8192000)*1024), mem.usedBytes)
	assert.Equal(t, 50.0, mem.usagePercent)
}

func TestReadMemInfo_NoMemAvailable(t *testing.T) {
	content := `MemTotal:       16384000 kB
MemFree:         4096000 kB
Buffers:          512000 kB
Cached:          2048000 kB
`
	path := writeFixture(t, "meminfo", content)

	mem, err := readMemInfo(path)
	assert.NoError(t, err)

	// Fallback: available = MemFree + Buffers + Cached = 6656000
	expectedUsed := uint64((16384000 - 6656000) * 1024)
	assert.Equal(t, uint64(16384000*1024), mem.totalBytes)
	assert.Equal(t, expectedUsed, mem.usedBytes)
}

func TestReadMemInfo_MissingMemTotal(t *testing.T) {
	content := `MemFree:         4096000 kB
MemAvailable:    8192000 kB
`
	path := writeFixture(t, "meminfo", content)

	_, err := readMemInfo(path)
	assert.Error(t, err)
}

func TestReadMemInfo_FileNotFound(t *testing.T) {
	_, err := readMemInfo("/nonexistent/meminfo")
	assert.Error(t, err)
}

func TestParseCPULine(t *testing.T) {
	// Fields: user nice system idle iowait irq softirq steal
	line := "cpu  100 20 30 500 10 5 3 2"
	ticks, err := parseCPULine(line)
	assert.NoError(t, err)

	// total = 100+20+30+500+10+5+3+2 = 670
	assert.Equal(t, uint64(670), ticks.total)
	// idle is the 4th field (index 3) = 500
	assert.Equal(t, uint64(500), ticks.idle)
}

func TestParseCPULine_WithGuestFields(t *testing.T) {
	line := "cpu  100 20 30 500 10 5 3 2 50 25"
	ticks, err := parseCPULine(line)
	assert.NoError(t, err)

	// total = 100+20+30+500+10+5+3+2+50+25 = 745
	assert.Equal(t, uint64(745), ticks.total)
	assert.Equal(t, uint64(500), ticks.idle)
}

func TestParseCPULine_TooFewFields(t *testing.T) {
	line := "cpu  100 20 30"
	_, err := parseCPULine(line)
	assert.Error(t, err)
}

func TestReadCPUTicks(t *testing.T) {
	content := `cpu  100 20 30 500 10 5 3 2
cpu0 50 10 15 250 5 3 1 1
cpu1 50 10 15 250 5 2 2 1
`
	path := writeFixture(t, "stat", content)

	ticks, err := readCPUTicks(path)
	assert.NoError(t, err)
	assert.Equal(t, uint64(670), ticks.total)
	assert.Equal(t, uint64(500), ticks.idle)
}

func TestReadCPUTicks_NoCPULine(t *testing.T) {
	content := `procs_running 2
procs_blocked 0
`
	path := writeFixture(t, "stat", content)

	_, err := readCPUTicks(path)
	assert.Error(t, err)
}

func TestReadCPUTicks_FileNotFound(t *testing.T) {
	_, err := readCPUTicks("/nonexistent/stat")
	assert.Error(t, err)
}

func TestReadMemInfo_FullyUsed(t *testing.T) {
	content := `MemTotal:       1024 kB
MemAvailable:      0 kB
`
	path := writeFixture(t, "meminfo", content)

	mem, err := readMemInfo(path)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1024*1024), mem.totalBytes)
	assert.Equal(t, uint64(1024*1024), mem.usedBytes)
	assert.Equal(t, 100.0, mem.usagePercent)
}

func TestReadMemInfo_NothingUsed(t *testing.T) {
	content := `MemTotal:       1024 kB
MemAvailable:   1024 kB
`
	path := writeFixture(t, "meminfo", content)

	mem, err := readMemInfo(path)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), mem.usedBytes)
	assert.Equal(t, 0.0, mem.usagePercent)
}
