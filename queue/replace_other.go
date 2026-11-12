//go:build !windows

package queue

import "os"

// atomicReplace uses POSIX rename semantics to preserve the old copy if an
// atomic replacement cannot be completed.
func atomicReplace(src, dst string) error { return os.Rename(src, dst) }
