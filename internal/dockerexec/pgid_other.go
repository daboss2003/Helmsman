//go:build !unix

package dockerexec

import "os/exec"

func setPgid(cmd *exec.Cmd) {}
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
