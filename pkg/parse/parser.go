package parse

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ParseOptions configures the parsing behavior
type ParseOptions struct {
	// Middleware to apply to all handlers
	GlobalStartMiddleware []Middleware
	GlobalEndMiddleware   []Middleware

	// Performance tuning
	EnableMetrics bool

	// Error handling
	StopOnError bool
}

// DefaultParseOptions provides sensible defaults
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		EnableMetrics: true,
		StopOnError:   true,
	}
}

type Parser struct {
	router  *Router
	engine  *ProcessingEngine
	options ParseOptions

	// Global middleware
	globalStart Middleware
	globalEnd   Middleware
}

func NewParser(opts ParseOptions) *Parser {
	engine := NewProcessingEngine()

	// Build global middleware chains
	var globalStart []Middleware
	var globalEnd []Middleware

	if opts.EnableMetrics {
		globalStart = append(globalStart, MetricsMiddleware("global.start"))
		globalEnd = append(globalEnd, MetricsMiddleware("global.end"))
	}

	// Add user-provided middleware
	globalStart = append(globalStart, opts.GlobalStartMiddleware...)
	globalEnd = append(globalEnd, opts.GlobalEndMiddleware...)

	return &Parser{
		router:      NewRouter(),
		engine:      engine,
		options:     opts,
		globalStart: Chain(globalStart...),
		globalEnd:   Chain(globalEnd...),
	}
}

// Selectable is implemented by handlers that carry their own path selector.
type Selectable interface {
	Selector() Selector
}

// Register registers a handler with an explicit selector.
func (p *Parser) Register(handler Handler, selector Selector) *Parser {
	// Wrap with global middleware if needed
	if p.globalStart != nil || p.globalEnd != nil {
		handler = &globalMiddlewareHandler{
			base:        handler,
			globalStart: p.globalStart,
			globalEnd:   p.globalEnd,
		}
	}

	p.router.Register(handler, selector)
	return p
}

// RegisterHandler registers a handler that exposes its own Selector().
func (p *Parser) RegisterHandler(handler Handler) *Parser {
	sel, ok := handler.(Selectable)
	if !ok {
		panic("RegisterHandler requires a handler that implements Selector()")
	}
	return p.Register(handler, sel.Selector())
}

// Metrics returns current metrics
func (p *Parser) Metrics() map[string]interface{} {
	return p.engine.metrics.ToJSON()
}

// ParseFile processes an XML file
func (p *Parser) ParseFile(ctx context.Context, filename string) (*ParseResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	return p.Parse(ctx, file)
}

func (p *Parser) Parse(ctx context.Context, r io.Reader) (*ParseResult, error) {
	// Create result container
	result := &ParseResult{
		StartTime: time.Now(),
		Engine:    p.engine,
	}

	// Create streaming handler with engine
	handler := NewStreamingHandler(p.router, p.engine)

	// Create XML decoder
	decoder := xml.NewDecoder(r)

	// Process tokens
	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, fmt.Errorf("decode token: %w", err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			if err := handler.HandleStartElement(ctx, t); err != nil {
				if p.options.StopOnError {
					return result, err
				}
				result.Errors = append(result.Errors, err)
			}

		case xml.EndElement:
			if err := handler.HandleEndElement(ctx, t); err != nil {
				if p.options.StopOnError {
					return result, err
				}
				result.Errors = append(result.Errors, err)
			}

		case xml.CharData:
			if err := handler.HandleCharData(ctx, t); err != nil {
				if p.options.StopOnError {
					return result, err
				}
				result.Errors = append(result.Errors, err)
			}
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// Close preserves a symmetric lifecycle for callers. All parser resources are
// synchronous, so there is nothing to drain.
func (p *Parser) Close(time.Duration) error { return nil }

// ============================================================================
// Updated StreamingHandler - Uses ProcessingEngine
// ============================================================================

type StreamingHandler struct {
	router       *Router
	engine       *ProcessingEngine
	elementStack []xml.StartElement
	pathStack    []string
	textStart    []int
	textTokens   []string
	pathBuilder  strings.Builder
}

func NewStreamingHandler(router *Router, engine *ProcessingEngine) *StreamingHandler {
	return &StreamingHandler{
		router:       router,
		engine:       engine,
		elementStack: make([]xml.StartElement, 0, 100),
		pathStack:    make([]string, 0, 100),
		textStart:    make([]int, 0, 100),
	}
}

func (h *StreamingHandler) HandleStartElement(ctx context.Context, se xml.StartElement) error {
	h.elementStack = append(h.elementStack, se)
	h.pathStack = append(h.pathStack, se.Name.Local)
	h.textStart = append(h.textStart, len(h.textTokens))

	// Build path efficiently
	h.pathBuilder.Reset()
	h.pathBuilder.WriteByte('/')
	for i, part := range h.pathStack {
		if i > 0 {
			h.pathBuilder.WriteByte('/')
		}
		h.pathBuilder.WriteString(part)
	}
	path := h.pathBuilder.String()

	// Push scope
	h.engine.scope.Push(path)

	// Create context through engine
	hctx := h.engine.CreateContext(path, se, "")

	// Execute handlers
	for _, handler := range h.router.Match(path) {
		if err := handler.Start()(ctx, hctx); err != nil {
			hctx.RecordError(err)
			return err
		}
	}

	return nil
}

func (h *StreamingHandler) HandleEndElement(ctx context.Context, ee xml.EndElement) error {
	if len(h.elementStack) == 0 {
		return nil
	}

	// Build path
	h.pathBuilder.Reset()
	h.pathBuilder.WriteByte('/')
	for i, part := range h.pathStack {
		if i > 0 {
			h.pathBuilder.WriteByte('/')
		}
		h.pathBuilder.WriteString(part)
	}
	path := h.pathBuilder.String()
	se := h.elementStack[len(h.elementStack)-1]

	text := ""
	if n := len(h.textStart); n > 0 {
		text = strings.Join(h.textTokens[h.textStart[n-1]:], " ")
	}

	// Create context with accumulated descendant text
	hctx := h.engine.CreateContext(path, se, text)

	// Execute handlers
	for _, handler := range h.router.Match(path) {
		if err := handler.End()(ctx, hctx); err != nil {
			hctx.RecordError(err)
			return err
		}
	}

	// Pop scope
	h.engine.scope.Pop()

	// Pop stacks
	h.elementStack = h.elementStack[:len(h.elementStack)-1]
	h.pathStack = h.pathStack[:len(h.pathStack)-1]
	if len(h.textStart) > 0 {
		h.textStart = h.textStart[:len(h.textStart)-1]
	}
	if len(h.textStart) == 0 {
		h.textTokens = h.textTokens[:0]
	}

	return nil
}

func (h *StreamingHandler) HandleCharData(ctx context.Context, cd xml.CharData) error {
	trimmed := strings.TrimSpace(string(cd))
	if trimmed == "" {
		return nil
	}
	// Store each token once. textStart lets every open element recover its
	// descendant text without copying the token once per XML depth.
	h.textTokens = append(h.textTokens, trimmed)
	return nil
}

type ParseResult struct {
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	Engine *ProcessingEngine
	Errors []error
}

// Results returns the result collector
func (pr *ParseResult) Results() *ResultStore {
	return pr.Engine.results
}
