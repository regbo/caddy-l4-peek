package l4peek

import (
	"bytes"
	"github.com/caddyserver/caddy/v2"
	"github.com/regbo/caddy-l4-peek/layer4"
	"io"
	"regexp"
)

func init() {
	caddy.RegisterModule(PeekMatcher{})
}

type PeekMatcher struct {
	PeekPrefixes       []string            `json:"prefixes,omitempty"`
	PeekPrefixPatterns []PeekPrefixPattern `json:"prefixPatterns,omitempty"`
	peekFilters        []peekFilter
}

type PeekPrefixPattern struct {
	Pattern string `json:"pattern,omitempty"`
	MaxRead uint32 `json:"maxRead,omitempty"`
}

type peekFilter struct {
	read uint32
	fn   func([]byte) bool
}

func (PeekMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.peek",
		New: func() caddy.Module { return new(PeekMatcher) },
	}
}

func (m *PeekMatcher) Provision(_ caddy.Context) error {
	for _, prefix := range m.PeekPrefixes {
		read := len(prefix)
		if read == 0 {
			continue
		}
		prefixBuf := []byte(prefix)
		m.peekFilters = append(m.peekFilters, peekFilter{uint32(read), func(buf []byte) bool {
			return bytes.HasPrefix(buf, prefixBuf)
		}})
	}
	for _, prefixPattern := range m.PeekPrefixPatterns {
		pattern := prefixPattern.Pattern
		if pattern == "" {
			continue
		}
		regexp := regexp.MustCompile(pattern)
		read := prefixPattern.MaxRead
		if read == 0 {
			read = maxReadDefault
		}
		m.peekFilters = append(m.peekFilters, peekFilter{uint32(read), func(buf []byte) bool {
			return regexp.Match(buf)
		}})
	}
	return nil
}

// Match returns true if the connection looks like it is using the SOCKSv5 protocol.
func (m *PeekMatcher) Match(cx *layer4.Connection) (bool, error) {
	var readTotal int
	var buf []byte
	for _, peekFilter := range m.peekFilters {
		if readTotal >= 0 {
			size := int(peekFilter.read) - readTotal
			if size > 0 {
				p := make([]byte, size)
				n, err := io.ReadFull(cx, p)
				if n < size || io.ErrUnexpectedEOF == err {
					readTotal = -1
				} else if err != nil {
					return false, nil
				} else {
					readTotal += n
					buf = append(buf, p...)
				}
			}
		}
		if peekFilter.fn(buf) {
			return true, nil
		}
	}
	return false, nil
}

const maxReadDefault uint32 = 4096

var (
	_ layer4.ConnMatcher = (*PeekMatcher)(nil)
	_ caddy.Provisioner  = (*PeekMatcher)(nil)
)
