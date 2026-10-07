// ocr-tesseract is an OCR program for the document adapter's page-text
// contract (docs/design/attachments.md, step 6): the page numbers as its
// arguments, the PDF on stdin, {"pages": [{"number", "text"}]} on stdout. It
// renders each page with Poppler's pdftoppm and reads it with Tesseract, both
// named by adapters/internal/ocrrender, through bounded pipes: no shell, no
// temporary document or image file, and nothing sent anywhere.
// `ocr-tesseract --check` exits 0 when both programs run and Tesseract has
// English data.
package main

import (
	"adapters/internal/ocrrender"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxPages      = 500
	maxInput      = 16 << 20
	maxImageBytes = 24 << 20
	maxPageText   = 2 << 20
	maxText       = 8 << 20
	deadline      = 120 * time.Second
)

// tools names the renderer and the recognizer. Tests replace it.
var tools = func() (renderer, engine ocrrender.Tool) {
	return ocrrender.Find("pdftoppm"), ocrrender.Find("tesseract")
}

func main() {
	if run(os.Args[1:], os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}

func run(args []string, input io.Reader, output io.Writer) error {
	renderer, engine := tools()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if len(args) == 1 && args[0] == "--check" {
		if _, e := ocrrender.Run(ctx, renderer, []string{"-v"}, nil, 64<<10); e != nil {
			return e
		}
		langs, e := ocrrender.Run(ctx, engine, []string{"--list-langs"}, nil, 64<<10)
		if e != nil {
			return e
		}
		for _, lang := range strings.Fields(string(langs)) {
			if lang == "eng" {
				return nil
			}
		}
		return errors.New("English OCR data unavailable")
	}
	// Every page number is held to its bounds before anything is read or run.
	if len(args) == 0 || len(args) > maxPages {
		return errors.New("invalid pages")
	}
	pages := make([]int, 0, len(args))
	seen := map[int]bool{}
	for _, arg := range args {
		n, e := strconv.Atoi(arg)
		if e != nil || strconv.Itoa(n) != arg || n < 1 || n > maxPages || seen[n] {
			return errors.New("invalid page")
		}
		seen[n] = true
		pages = append(pages, n)
	}
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil || len(data) == 0 || len(data) > maxInput {
		return errors.New("invalid PDF")
	}
	type page struct {
		Number int    `json:"number"`
		Text   string `json:"text"`
	}
	result := struct {
		Pages []page `json:"pages"`
	}{Pages: []page{}}
	total := 0
	for _, n := range pages {
		arg := strconv.Itoa(n)
		raster, e := ocrrender.Run(ctx, renderer, []string{"-f", arg, "-l", arg, "-scale-to", strconv.Itoa(ocrrender.MaxScale), "-singlefile", "-png", "-"}, data, maxImageBytes)
		if e != nil {
			return e
		}
		text, e := ocrrender.Run(ctx, engine, []string{"stdin", "stdout", "-l", "eng"}, raster, maxPageText)
		if e != nil {
			return e
		}
		total += len(text)
		if total > maxText {
			return errors.New("text exceeds bound")
		}
		result.Pages = append(result.Pages, page{n, string(text)})
	}
	return json.NewEncoder(output).Encode(result)
}
