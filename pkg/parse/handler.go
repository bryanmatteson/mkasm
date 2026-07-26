package parse

import (
	"context"
)

// HandlerFunc is the basic handler signature for both Start and End
type HandlerFunc func(ctx context.Context, hctx *HandlerContext) error

type Handler interface {
	Start() HandlerFunc
	End() HandlerFunc
}

// TypedHandler now composes middleware with typed processing
type TypedHandler[TContext any, TResult any] struct {
	selector Selector
	name     string
	sessions *SessionManager

	// Middleware chains
	startMiddleware Middleware
	endMiddleware   Middleware

	// Core processing functions
	createContext func(*HandlerContext) TContext
	processStart  func(context.Context, TContext, *HandlerContext) error
	processEnd    func(context.Context, TContext, *HandlerContext) (TResult, error)
	handleResult  func(context.Context, TResult, *HandlerContext) error
}

// Builder pattern for clean configuration
type TypedHandlerBuilder[TContext any, TResult any] struct {
	handler *TypedHandler[TContext, TResult]
}

func NewTypedHandlerBuilder[TContext any, TResult any](name string, selector Selector) *TypedHandlerBuilder[TContext, TResult] {
	return &TypedHandlerBuilder[TContext, TResult]{
		handler: &TypedHandler[TContext, TResult]{
			selector:        selector,
			name:            name,
			sessions:        NewSessionManager(),
			startMiddleware: Chain(), // empty chain
			endMiddleware:   Chain(), // empty chain
		},
	}
}

func (b *TypedHandlerBuilder[T, R]) WithStartMiddleware(m ...Middleware) *TypedHandlerBuilder[T, R] {
	b.handler.startMiddleware = Chain(m...)
	return b
}

func (b *TypedHandlerBuilder[T, R]) WithContextCreator(f func(*HandlerContext) T) *TypedHandlerBuilder[T, R] {
	b.handler.createContext = f
	return b
}

func (b *TypedHandlerBuilder[T, R]) WithStartProcessor(f func(context.Context, T, *HandlerContext) error) *TypedHandlerBuilder[T, R] {
	b.handler.processStart = f
	return b
}

func (b *TypedHandlerBuilder[T, R]) WithEndProcessor(f func(context.Context, T, *HandlerContext) (R, error)) *TypedHandlerBuilder[T, R] {
	b.handler.processEnd = f
	return b
}

func (b *TypedHandlerBuilder[T, R]) WithResultHandler(f func(context.Context, R, *HandlerContext) error) *TypedHandlerBuilder[T, R] {
	b.handler.handleResult = f
	return b
}

func (b *TypedHandlerBuilder[T, R]) Build() Handler {
	return b.handler
}

// Selector returns the path selector for this handler.
func (h *TypedHandler[T, R]) Selector() Selector {
	return h.selector
}

func (h *TypedHandler[T, R]) Start() HandlerFunc {
	coreStart := func(ctx context.Context, hctx *HandlerContext) error {
		// Create context
		tctx := h.createContext(hctx)

		// Store in session for End phase
		SessionStore(h.sessions, hctx.Path, tctx)

		// Process start
		if h.processStart != nil {
			return h.processStart(ctx, tctx, hctx)
		}
		return nil
	}

	return h.startMiddleware(coreStart)
}

func (h *TypedHandler[T, R]) End() HandlerFunc {
	coreEnd := func(ctx context.Context, hctx *HandlerContext) error {
		// Retrieve from session
		tctx, exists := SessionLoad[T](h.sessions, hctx.Path)
		if !exists {
			// Start was skipped (e.g. When middleware) — nothing to finish
			return nil
		}

		// Clean up session
		h.sessions.Delete(hctx.Path)

		// Process end
		if h.processEnd != nil {
			result, err := h.processEnd(ctx, tctx, hctx)
			if err != nil {
				return err
			}

			if h.handleResult != nil {
				return h.handleResult(ctx, result, hctx)
			}
		}

		return nil
	}

	return h.endMiddleware(coreEnd)
}

type FuncHandler struct {
	selector  Selector
	startFunc HandlerFunc
	endFunc   HandlerFunc
}

func NewFuncHandler(selector Selector, start, end HandlerFunc) Handler {
	if start == nil {
		start = func(context.Context, *HandlerContext) error { return nil }
	}
	if end == nil {
		end = func(context.Context, *HandlerContext) error { return nil }
	}
	return &FuncHandler{
		selector:  selector,
		startFunc: start,
		endFunc:   end,
	}
}

func (f *FuncHandler) Selector() Selector { return f.selector }
func (f *FuncHandler) Start() HandlerFunc { return f.startFunc }
func (f *FuncHandler) End() HandlerFunc   { return f.endFunc }

type globalMiddlewareHandler struct {
	base        Handler
	globalStart Middleware
	globalEnd   Middleware
}

func (g *globalMiddlewareHandler) Start() HandlerFunc {
	base := g.base.Start()
	if base == nil {
		base = func(context.Context, *HandlerContext) error { return nil }
	}
	if g.globalStart == nil {
		return base
	}
	return g.globalStart(base)
}

func (g *globalMiddlewareHandler) End() HandlerFunc {
	base := g.base.End()
	if base == nil {
		base = func(context.Context, *HandlerContext) error { return nil }
	}
	if g.globalEnd == nil {
		return base
	}
	return g.globalEnd(base)
}

type SessionManager struct {
	sessions map[string]any
}

func NewSessionManager() *SessionManager {
	return &SessionManager{sessions: make(map[string]any)}
}

func (sm *SessionManager) Store(path string, data any) {
	sm.sessions[path] = data
}

func (sm *SessionManager) Load(path string) (any, bool) {
	data, ok := sm.sessions[path]
	return data, ok
}

func (sm *SessionManager) Delete(path string) {
	delete(sm.sessions, path)
}

// Type-safe session storage
func SessionStore[T any](sm *SessionManager, path string, value T) {
	sm.Store(path, value)
}

func SessionLoad[T any](sm *SessionManager, path string) (T, bool) {
	val, ok := sm.Load(path)
	if !ok {
		var zero T
		return zero, false
	}
	typed, ok := val.(T)
	return typed, ok
}
