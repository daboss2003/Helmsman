//go:build unix

package dockerexec

import (
	"os/exec"
	"syscall"
)

// setPgid puts the child in its own process group so the whole tree can be
// signalled at once (docker compose spawns helpers).
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup SIGKILLs the child's process group (negative pid).
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
