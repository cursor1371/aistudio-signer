package mozjs

import (
	"runtime"
	"testing"
)

// Exercise the native ABI and microtask loop without WAA, accounts or network.
func TestEngineEvaluation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cx, err := NewContext(Options{HeapBytes: 64 << 20, Locale: "en-US"})
	if err != nil {
		t.Fatal(err)
	}
	defer cx.Close()
	global, err := cx.NewGlobal(0, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	defer cx.Release(global)

	value, err := cx.Evaluate(global, "Promise.resolve(41).then(value => { globalThis.answer = value + 1; });", "release-smoke.js", 1)
	if err != nil {
		t.Fatal(err)
	}
	cx.ReleaseValue(value)
	cx.RunJobs()
	answer, err := cx.Get(global, "answer")
	if err != nil {
		t.Fatal(err)
	}
	defer cx.ReleaseValue(answer)
	if answer.Kind != KindNumber || answer.Number != 42 {
		t.Fatalf("unexpected local evaluation result: kind=%v number=%v", answer.Kind, answer.Number)
	}
}
