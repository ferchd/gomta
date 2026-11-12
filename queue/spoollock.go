package queue

import (
	"fmt"
	"os"
	"path/filepath"
)

// acquireSpoolLock holds an OS-managed advisory file lock until release.
// The lock file must not be removed: other processes may still hold its inode.
func acquireSpoolLock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".gomta-spool.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil { return nil, err }
	if err := lockSpoolFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another process may already own this spool: %w", err)
	}
	return func() {
		_ = unlockSpoolFile(f)
		_ = f.Close()
	}, nil
}
