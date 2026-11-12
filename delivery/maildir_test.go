package delivery
import "testing"
func TestSafeComponentStable(t *testing.T) {
    a := safeComponent("person+ñ")
    if a != safeComponent("person+ñ") { t.Fatalf("unstable mailbox directory: %q", a) }
    if a == safeComponent("person+?") { t.Fatal("different recipients collided") }
    long := "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij"
    if len(safeComponent(long)) > 120 { t.Fatalf("unsafe length: %d", len(safeComponent(long))) }
}
