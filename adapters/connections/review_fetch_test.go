//go:build linux || darwin

package connections

import (
	"context"

	"testing"
)

// esc builds a JSON unicode escape without putting one in this source file.
func esc(hex string) string { return "\\" + "u" + hex }

func fetchWith(t *testing.T, text string) ([]byte, error) {
	t.Helper()
	b, _ := notionFixture(t)
	connectNotion(t, b)
	v, _ := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`))
	got, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{testPage}, "selectionContext": v.(SourceSearch).SelectionContext}))
	if err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = mcpOverride(b.provider.client.Transport, "notion-fetch", func() string { return text }, nil)
	return b.provider.readNotion(context.Background(), b.store, mustJSON(got.([]SourceSelection)[0]))
}
