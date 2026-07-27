package parse

import (
	"encoding/xml"
	"time"
)

type ProcessingEngine struct {
	metrics *MetricsCollector
	results *ResultStore
	scope   *ScopeStack
}

func NewProcessingEngine() *ProcessingEngine {
	return &ProcessingEngine{
		metrics: NewMetricsCollector(),
		results: NewResultStore(),
		scope:   NewScopeStack(),
	}
}

func (pe *ProcessingEngine) CreateContext(path string, element xml.StartElement, text string) *HandlerContext {
	return NewHandlerContext(path, element, text, &ContextServices{
		metrics: pe.metrics,
		results: pe.results,
		scope:   pe.scope,
	})
}

type ContextServices struct {
	metrics *MetricsCollector
	results *ResultStore
	scope   *ScopeStack
}

type MetricsCollector struct {
	startTime time.Time
	counters  map[string]int64
	durations map[string]durationAccumulator
	errors    int64
}

type durationAccumulator struct {
	total time.Duration
	count int64
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		startTime: time.Now(),
		counters:  make(map[string]int64),
		durations: make(map[string]durationAccumulator),
	}
}

func (m *MetricsCollector) RecordDuration(name string, duration time.Duration) {
	acc := m.durations[name]
	acc.total += duration
	acc.count++
	m.durations[name] = acc
}

func (m *MetricsCollector) IncrementCounter(name string) {
	m.counters[name]++
}

func (m *MetricsCollector) RecordError(error, string) {
	m.errors++
}

func (m *MetricsCollector) ToJSON() map[string]any {
	result := map[string]any{
		"duration_ms": time.Since(m.startTime).Milliseconds(),
		"errors":      m.errors,
		"counters":    make(map[string]int64),
		"durations":   make(map[string]map[string]any),
	}

	counters := result["counters"].(map[string]int64)
	for name, count := range m.counters {
		counters[name] = count
	}

	durations := result["durations"].(map[string]map[string]any)
	for name, acc := range m.durations {
		total, count := acc.total, acc.count
		average := time.Duration(0)
		if count != 0 {
			average = total / time.Duration(count)
		}
		durations[name] = map[string]any{
			"total_ms": total.Milliseconds(),
			"avg_ms":   average.Milliseconds(),
			"count":    count,
		}
	}
	return result
}

// ResultStore is the deliberately small handoff between streaming Pass 1
// handlers and the ARM pipeline.
type ResultStore struct {
	values map[string][]any
}

func NewResultStore() *ResultStore {
	return &ResultStore{values: make(map[string][]any)}
}

func (rs *ResultStore) StoreWithPath(resultType, _ string, result any) {
	rs.values[resultType] = append(rs.values[resultType], result)
}

func GetResults[T any](rs *ResultStore, resultType string) []T {
	values := rs.values[resultType]
	out := make([]T, 0, len(values))
	for _, value := range values {
		if typed, ok := value.(T); ok {
			out = append(out, typed)
		}
	}
	return out
}

type ScopeContext struct {
	Parent  *ScopeContext
	storage map[string]any
}

func ScopeStore[T any](scope *ScopeContext, key string, value T) {
	if scope.storage == nil {
		scope.storage = make(map[string]any)
	}
	scope.storage[key] = value
}

func ScopeLoad[T any](scope *ScopeContext, key string) (T, bool) {
	value, ok := scope.storage[key]
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := value.(T)
	return typed, ok
}

type ScopeStack struct {
	stack []*ScopeContext
	free  []*ScopeContext
}

func NewScopeStack() *ScopeStack {
	return &ScopeStack{stack: make([]*ScopeContext, 0, 100)}
}

func (sm *ScopeStack) Push(_ string) {
	var parent *ScopeContext
	if len(sm.stack) != 0 {
		parent = sm.stack[len(sm.stack)-1]
	}
	var scope *ScopeContext
	if n := len(sm.free); n != 0 {
		scope = sm.free[n-1]
		sm.free = sm.free[:n-1]
		scope.Parent = parent
	} else {
		scope = &ScopeContext{Parent: parent}
	}
	sm.stack = append(sm.stack, scope)
}

func (sm *ScopeStack) Pop() {
	if len(sm.stack) != 0 {
		n := len(sm.stack) - 1
		scope := sm.stack[n]
		sm.stack = sm.stack[:n]
		scope.Parent = nil
		if scope.storage != nil {
			clear(scope.storage)
			scope.storage = nil
		}
		sm.free = append(sm.free, scope)
	}
}

func (sm *ScopeStack) Current() *ScopeContext {
	if len(sm.stack) == 0 {
		return nil
	}
	return sm.stack[len(sm.stack)-1]
}
