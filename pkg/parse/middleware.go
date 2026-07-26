package parse

import (
	"context"
	"time"
)

// Middleware wraps a HandlerFunc to add behavior
type Middleware func(HandlerFunc) HandlerFunc

// Chain combines multiple middleware into one
func Chain(middlewares ...Middleware) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// MetricsMiddleware now uses the clean API
func MetricsMiddleware(metricName string) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, hctx *HandlerContext) error {
			start := time.Now()
			err := next(ctx, hctx)
			hctx.RecordDuration(metricName, time.Since(start))
			return err
		}
	}
}

// Conditional execution
func When(condition func(*HandlerContext) bool) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, hctx *HandlerContext) error {
			if condition(hctx) {
				return next(ctx, hctx)
			}
			return nil
		}
	}
}
