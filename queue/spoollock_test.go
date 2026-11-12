package queue

import "testing"

func TestSpoolLockRejectsSecondOwner(t *testing.T) {
	dir:=t.TempDir()
	release,err:=acquireSpoolLock(dir)
	if err!=nil {t.Fatal(err)}
	if other,err:=acquireSpoolLock(dir);err==nil {
		other()
		release()
		t.Fatal("second spool owner was not rejected")
	}
	release()
	third,err:=acquireSpoolLock(dir)
	if err!=nil {t.Fatalf("released spool cannot be reused: %v",err)}
	third()
}
