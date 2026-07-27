package parse

import "testing"

func TestScopeStackReusesEmptyContextsWithoutLeakingState(t *testing.T) {
	stack := NewScopeStack()
	stack.Push("root")
	root := stack.Current()
	ScopeStore(root, "root", 1)

	stack.Push("first")
	first := stack.Current()
	ScopeStore(first, "child", 2)
	if got, ok := ScopeLoad[int](first.Parent, "root"); !ok || got != 1 {
		t.Fatalf("load from parent = %d, %v; want 1, true", got, ok)
	}
	stack.Pop()

	stack.Push("second")
	second := stack.Current()
	if second != first {
		t.Fatal("popped scope was not reused")
	}
	if second.Parent != root {
		t.Fatal("reused scope has the wrong parent")
	}
	if _, ok := ScopeLoad[int](second, "child"); ok {
		t.Fatal("reused scope retained child state")
	}
}
