package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type SystemInfo struct {
	MemTotalBytes   uint64  `json:"mem_total_bytes"`
	MemUsedBytes    uint64  `json:"mem_used_bytes"`
	MemUsagePercent float64 `json:"mem_usage_percent"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	NumCPUs         int     `json:"num_cpus"`
}

const cpuSampleInterval = 100 * time.Millisecond

func getSystemInfoOrNil() *SystemInfo {
	info, err := GetSystemInfo()
	if err != nil {
		log.Printf("WARN: Failed to collect system info: %v", err)
		return nil
	}
	return info
}

func GetSystemInfo() (*SystemInfo, error) {
	mem, err := readMemInfo("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("reading meminfo: %w", err)
	}

	cpuPct, err := sampleCPUUsage("/proc/stat", cpuSampleInterval)
	if err != nil {
		return nil, fmt.Errorf("reading cpu stats: %w", err)
	}

	return &SystemInfo{
		MemTotalBytes:   mem.totalBytes,
		MemUsedBytes:    mem.usedBytes,
		MemUsagePercent: mem.usagePercent,
		CPUUsagePercent: cpuPct,
		NumCPUs:         runtime.NumCPU(),
	}, nil
}

type memStats struct {
	totalBytes   uint64
	usedBytes    uint64
	usagePercent float64
}

func readMemInfo(path string) (*memStats, error) {
	fields, err := parseKeyValueKB(path, "MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached")
	if err != nil {
		return nil, err
	}

	total, ok := fields["MemTotal"]
	if !ok || total == 0 {
		return nil, fmt.Errorf("MemTotal not found or zero in %s", path)
	}

	available, hasAvailable := fields["MemAvailable"]
	if !hasAvailable {
		// Kernel <3.14 fallback
		free := fields["MemFree"]
		buffers := fields["Buffers"]
		cached := fields["Cached"]
		available = free + buffers + cached
	}

	totalBytes := total * 1024
	var usedBytes uint64
	if total > available {
		usedBytes = (total - available) * 1024
	}
	pct := float64(usedBytes) / float64(totalBytes) * 100
	pct = math.Round(pct*10) / 10

	return &memStats{
		totalBytes:   totalBytes,
		usedBytes:    usedBytes,
		usagePercent: pct,
	}, nil
}

// parseKeyValueKB reads /proc/meminfo-style files and returns values in kB for
// the requested keys.
func parseKeyValueKB(path string, keys ...string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}

	result := make(map[string]uint64, len(keys))
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := parseMemInfoLine(line)
		if ok && want[key] {
			result[key] = val
		}
	}
	return result, scanner.Err()
}

// parseMemInfoLine parses a single line like "MemTotal:       16384 kB" and
// returns (key, valueInKB, ok).
func parseMemInfoLine(line string) (string, uint64, bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", 0, false
	}
	key := line[:colon]
	rest := strings.TrimSpace(line[colon+1:])

	rest = strings.TrimSuffix(rest, " kB")
	val, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return key, val, true
}

type cpuTicks struct {
	total uint64
	idle  uint64
}

func readCPUTicks(path string) (*cpuTicks, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			return parseCPULine(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no aggregate cpu line found in %s", path)
}

// parseCPULine parses the aggregate "cpu  ..." line from /proc/stat.
// Fields: user nice system idle iowait irq softirq steal [guest guest_nice]
//
// guest and guest_nice are already accounted for in user and nice, so we
// only sum the first 8 fields to avoid double-counting.
func parseCPULine(line string) (*cpuTicks, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("unexpected cpu line format: %q", line)
	}

	numFields := len(fields) - 1 // exclude "cpu" label
	if numFields > 8 {
		numFields = 8
	}

	var total, idle uint64
	for i, f := range fields[1 : 1+numFields] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing field %d of cpu line: %w", i, err)
		}
		total += v
		if i == 3 {
			idle = v
		}
	}
	return &cpuTicks{total: total, idle: idle}, nil
}

func sampleCPUUsage(path string, interval time.Duration) (float64, error) {
	t1, err := readCPUTicks(path)
	if err != nil {
		return 0, err
	}

	time.Sleep(interval)

	t2, err := readCPUTicks(path)
	if err != nil {
		return 0, err
	}

	totalDelta := t2.total - t1.total
	idleDelta := t2.idle - t1.idle

	if totalDelta == 0 {
		return 0, nil
	}

	pct := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	return math.Round(pct*10) / 10, nil
}
