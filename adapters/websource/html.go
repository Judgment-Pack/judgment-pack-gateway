package websource

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Static text only: scripts/styles/templates are not content, no remote assets
// are fetched, and no browser layout or JavaScript execution is claimed.
func staticText(ctx context.Context, raw []byte) ([]byte, string, error) {
	if !utf8.Valid(raw) {
		return nil, "", ErrMedia
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	z.SetMaxBuf(MaxBytes)
	var out, title strings.Builder
	suppressed, inTitle := "", false
	depth := 0
	for {
		if ctx.Err() != nil {
			return nil, "", ErrNetwork
		}
		kind := z.Next()
		switch kind {
		case html.ErrorToken:
			if !errors.Is(z.Err(), io.EOF) {
				return nil, "", ErrMedia
			}
			lines := make([]string, 0)
			for _, line := range strings.Split(out.String(), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					lines = append(lines, line)
				}
			}
			text := strings.Join(lines, "\n\n")
			if len(text) > MaxBytes {
				return nil, "", ErrLimit
			}
			if text == "" {
				return nil, "", ErrMedia
			}
			return []byte(text), strings.TrimSpace(title.String()), nil
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if suppressed != "" {
				if tag == suppressed && (kind == html.StartTagToken || tag != "svg") {
					depth++
				}
				continue
			}
			switch tag {
			case "script", "style", "template", "noscript", "svg":
				if kind == html.StartTagToken || tag != "svg" {
					suppressed = tag
					depth = 1
				}
				continue
			}
			if tag == "title" {
				inTitle = true
			}
			if block(tag) {
				out.WriteByte('\n')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if suppressed != "" {
				if tag == suppressed {
					depth--
					if depth == 0 {
						suppressed = ""
					}
				}
				continue
			}
			if tag == "title" {
				inTitle = false
			}
			if block(tag) {
				out.WriteByte('\n')
			}
		case html.TextToken:
			if suppressed != "" {
				continue
			}
			text := strings.Join(strings.Fields(string(z.Text())), " ")
			if text != "" {
				if inTitle {
					if title.Len() < 1024 {
						title.WriteString(text)
						title.WriteByte(' ')
					}
				} else {
					out.WriteString(text)
					out.WriteByte(' ')
				}
			}
		}
		if out.Len() > MaxBytes {
			return nil, "", ErrLimit
		}
	}
}
func block(tag string) bool {
	switch tag {
	case "br", "p", "div", "article", "section", "main", "header", "footer", "nav", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "title":
		return true
	}
	return false
}
