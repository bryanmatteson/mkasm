package parse

import (
	"encoding/xml"
	"time"
)

// HandlerContext is the immutable XML view plus the small set of shared
// services handlers need while a token is processed.
type HandlerContext struct {
	Path    string
	Element xml.StartElement
	Text    string

	services *ContextServices
}

func NewHandlerContext(path string, element xml.StartElement, text string, services *ContextServices) *HandlerContext {
	return &HandlerContext{
		Path:     path,
		Element:  element,
		Text:     text,
		services: services,
	}
}

func (hctx *HandlerContext) RecordDuration(name string, duration time.Duration) {
	hctx.services.metrics.RecordDuration(name, duration)
}

func (hctx *HandlerContext) StoreResult(resultType string, result any) {
	hctx.services.results.StoreWithPath(resultType, hctx.Path, result)
}

func (hctx *HandlerContext) RecordError(err error) {
	hctx.services.metrics.RecordError(err, hctx.Path)
}

func (hctx *HandlerContext) IncrementCounter(name string) {
	hctx.services.metrics.IncrementCounter(name)
}

func StoreInScope[T any](hctx *HandlerContext, key string, value T) {
	if scope := hctx.services.scope.Current(); scope != nil {
		ScopeStore(scope, key, value)
	}
}

func LoadFromScope[T any](hctx *HandlerContext, key string) (T, bool) {
	for scope := hctx.services.scope.Current(); scope != nil; scope = scope.Parent {
		if value, ok := ScopeLoad[T](scope, key); ok {
			return value, true
		}
	}
	var zero T
	return zero, false
}
