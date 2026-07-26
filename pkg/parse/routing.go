package parse

import "strings"

type Selector func(path string) bool

var Select = struct {
	Element func(...string) Selector
}{
	Element: func(elements ...string) Selector {
		return func(path string) bool {
			name := path
			if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
				name = path[slash+1:]
			}
			for _, element := range elements {
				if name == element {
					return true
				}
			}
			return false
		}
	},
}

type Route struct {
	Handler  Handler
	Selector Selector
}

type Router struct {
	routes []Route
	cache  map[string][]Handler
}

func NewRouter() *Router {
	return &Router{cache: make(map[string][]Handler)}
}

func (r *Router) Register(handler Handler, selector Selector) *Router {
	r.routes = append(r.routes, Route{Handler: handler, Selector: selector})
	clear(r.cache)
	return r
}

func (r *Router) Match(path string) []Handler {
	if matched, ok := r.cache[path]; ok {
		return matched
	}
	var matched []Handler
	for _, route := range r.routes {
		if route.Selector(path) {
			matched = append(matched, route.Handler)
		}
	}
	r.cache[path] = matched
	return matched
}
