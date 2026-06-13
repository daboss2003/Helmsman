//go:build !linux

package hostmon

// Non-Linux stubs (Helmsman targets Linux/systemd). These keep the binary
// building on dev machines; Sample surfaces ErrUnsupported, which the monitor
// logs once and treats as "host metrics unavailable" without failing app polling.

func readCPUTimes() (busy, total uint64, err error)        { return 0, 0, ErrUnsupported }
func readMem() (total, used uint64, err error)             { return 0, 0, ErrUnsupported }
func readLoad1() (float64, error)                          { return 0, ErrUnsupported }
func readDisk(path string) (total, used uint64, err error) { return 0, 0, ErrUnsupported }
