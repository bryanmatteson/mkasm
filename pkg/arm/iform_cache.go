package arm

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ParsedIFormCache caches ParseIFormFile results keyed by path + encodingID.
// A non-positive maxSize means unbounded; ARMParser uses that mode because the
// cache lives for one pipeline run and Pass 3 immediately reuses all Pass 2
// forms. Callers processing an open-ended stream can supply a positive bound.
type ParsedIFormCache struct {
	mu      sync.RWMutex
	data    map[string]*ParsedIForm
	maxSize int
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewParsedIFormCache(maxSize int) *ParsedIFormCache {
	return &ParsedIFormCache{
		data:    make(map[string]*ParsedIForm),
		maxSize: maxSize,
	}
}

func cacheKey(path, encodingID string) string {
	return path + "\x00" + encodingID
}

func (c *ParsedIFormCache) GetOrLoad(path, encodingID string) (*ParsedIForm, error) {
	return c.getOrLoad(path, encodingID, func() (*ParsedIForm, error) {
		return ParseIFormFile(path, encodingID)
	})
}

func (c *ParsedIFormCache) GetOrLoadCorpus(corpus XMLCorpus, name, encodingID string) (*ParsedIForm, error) {
	if prepared, ok := corpus.(interface {
		preparedIForm(name, encodingID string) (*ParsedIForm, bool)
	}); ok {
		form, found := prepared.preparedIForm(name, encodingID)
		if !found {
			return nil, fmt.Errorf("prepared corpus has no encoding %q in %q", encodingID, name)
		}
		return c.getOrLoad(name, encodingID, func() (*ParsedIForm, error) {
			return form, nil
		})
	}
	return c.getOrLoad(name, encodingID, func() (*ParsedIForm, error) {
		r, err := corpus.OpenXML(name)
		if errors.Is(err, ErrCorpusEntryUnavailable) {
			return &ParsedIForm{}, nil
		}
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return parseIForm(r, encodingID)
	})
}

func (c *ParsedIFormCache) getOrLoad(path, encodingID string, load func() (*ParsedIForm, error)) (*ParsedIForm, error) {
	key := cacheKey(path, encodingID)
	c.mu.RLock()
	if p, ok := c.data[key]; ok {
		c.mu.RUnlock()
		c.hits.Add(1)
		return p, nil
	}
	c.mu.RUnlock()

	c.misses.Add(1)
	parsed, err := load()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.data[key]; ok {
		return existing, nil
	}
	if c.maxSize > 0 && len(c.data) >= c.maxSize {
		// Drop an arbitrary entry; Pass 2 is short-lived so LRU is unnecessary.
		for k := range c.data {
			delete(c.data, k)
			break
		}
	}
	c.data[key] = parsed
	return parsed, nil
}

func (c *ParsedIFormCache) Hits() int64   { return c.hits.Load() }
func (c *ParsedIFormCache) Misses() int64 { return c.misses.Load() }

func (c *ParsedIFormCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*ParsedIForm)
}
