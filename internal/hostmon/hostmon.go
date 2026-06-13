// Package hostmon samples host CPU/RAM/disk for the read plane (plan §4). The
// parsing is pure and unit-tested cross-platform; the actual /proc + statfs reads
// are Linux-specific (the deploy target), with a no-op stub elsewhere so the
// binary still builds on a dev machine.
package hostmon

import (
	"errors"
	"strconv"
	"strings"
)

// ErrUnsupported is returned by Sample on non-Linux platforms.
var ErrUnsupported = errors.New("hostmon: host metrics not supported on this platform")

// Sample is one host metrics reading.
type Sample struct {
	CPUPercent float64
	Load1      float64
	MemTotal   uint64
	MemUsed    uint64
	DiskTotal  uint64
	DiskUsed   uint64
}

// Sampler holds the previous CPU counters so it can compute instantaneous CPU%
// from the delta between successive Sample calls.
type Sampler struct {
	diskPath  string
	prevBusy  uint64
	prevTotal uint64
	havePrev  bool
}

// New returns a Sampler that measures disk usage at diskPath.
func New(diskPath string) *Sampler { return &Sampler{diskPath: diskPath} }

// Sample reads current host metrics. CPU% is 0 on the first call (no prior
// counters to diff against).
func (s *Sampler) Sample() (Sample, error) {
	busy, total, err := readCPUTimes()
	if err != nil {
		return Sample{}, err
	}
	cpu := cpuPercent(s.havePrev, s.prevBusy, s.prevTotal, busy, total)
	s.prevBusy, s.prevTotal, s.havePrev = busy, total, true

	memTotal, memUsed, err := readMem()
	if err != nil {
		return Sample{}, err
	}
	load1, _ := readLoad1() // non-fatal
	diskTotal, diskUsed, err := readDisk(s.diskPath)
	if err != nil {
		return Sample{}, err
	}
	return Sample{
		CPUPercent: cpu, Load1: load1,
		MemTotal: memTotal, MemUsed: memUsed,
		DiskTotal: diskTotal, DiskUsed: diskUsed,
	}, nil
}

// cpuPercent computes CPU% from busy/total jiffy counters versus the previous
// sample. The subtraction is done in float64 (NOT uint64) and the numerator is
// clamped at 0 so a non-monotonic counter (iowait can decrease, CPU hotplug) can
// never underflow into an astronomical value (review #2/#6); the result is
// clamped to [0,100] (aggregate host CPU is already total-normalized).
func cpuPercent(havePrev bool, prevBusy, prevTotal, busy, total uint64) float64 {
	if !havePrev {
		return 0
	}
	db := float64(busy) - float64(prevBusy)
	dt := float64(total) - float64(prevTotal)
	if db < 0 {
		db = 0
	}
	if dt <= 0 {
		return 0
	}
	cpu := db / dt * 100.0
	if cpu > 100 {
		cpu = 100
	}
	return cpu
}

// parseProcStat parses the aggregate "cpu" line of /proc/stat into busy/total
// jiffies. total = sum of all fields; busy = total - (idle + iowait).
func parseProcStat(data string) (busy, total uint64, err error) {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // drop "cpu"
		var idle uint64
		for i, f := range fields {
			v, perr := strconv.ParseUint(f, 10, 64)
			if perr != nil {
				return 0, 0, perr
			}
			total += v
			if i == 3 || i == 4 { // idle, iowait
				idle += v
			}
		}
		return total - idle, total, nil
	}
	return 0, 0, errors.New("hostmon: no cpu line in /proc/stat")
}

// parseMemInfo parses /proc/meminfo into total/used bytes (used = total -
// available).
func parseMemInfo(data string) (total, used uint64, err error) {
	var memTotal, memAvail uint64
	var haveTotal, haveAvail bool
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, perr := strconv.ParseUint(fields[1], 10, 64)
		if perr != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotal, haveTotal = v*1024, true
		case "MemAvailable:":
			memAvail, haveAvail = v*1024, true
		}
	}
	if !haveTotal || !haveAvail {
		return 0, 0, errors.New("hostmon: missing MemTotal/MemAvailable")
	}
	if memAvail > memTotal {
		memAvail = memTotal
	}
	return memTotal, memTotal - memAvail, nil
}

// parseLoadAvg parses the 1-minute load from /proc/loadavg.
func parseLoadAvg(data string) (float64, error) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, errors.New("hostmon: empty loadavg")
	}
	return strconv.ParseFloat(fields[0], 64)
}
