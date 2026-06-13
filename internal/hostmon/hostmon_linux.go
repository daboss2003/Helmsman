//go:build linux

package hostmon

import (
	"os"
	"syscall"
)

func readCPUTimes() (busy, total uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	return parseProcStat(string(data))
}

func readMem() (total, used uint64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	return parseMemInfo(string(data))
}

func readLoad1() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	return parseLoadAvg(string(data))
}

func readDisk(path string) (total, used uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize
	free := st.Bfree * bsize
	if free > total {
		free = total
	}
	return total, total - free, nil
}
