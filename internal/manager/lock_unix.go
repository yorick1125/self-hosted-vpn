//go:build unix

package manager

import (
	"fmt"
	"os"
	"syscall"
)

// lock takes an exclusive lock on dir so two wgm processes can never hand
// out the same IP or interleave edits to the server config.
func lock(dir string) (unlock func(), err error) {
	f, err := os.OpenFile(dir+"/.wgm.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another wgm command is running (lock %s): %w", f.Name(), err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
