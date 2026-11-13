package plugin

import "sync"

// BodyLease keeps retained plugin output charged until its transaction
// replaces or finishes using that body. Release is idempotent.
type BodyLease struct {
	budget *ByteBudget
	size   int64
	once   sync.Once
}

func (l *BodyLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.budget != nil && l.size > 0 {
			l.budget.Release(l.size)
		}
	})
}
func (pr *PluginResult) releaseBodyLease() {
	if pr.bodyLease != nil {
		pr.bodyLease.Release()
		pr.bodyLease = nil
	}
}
