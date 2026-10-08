// ocr-cloud is the cloud OCR worker for the document adapter's page-text
// contract, run for the operator's document-processing settings.
package main

import (
	"adapters/connections"
	"context"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// The page numbers are the arguments; the processor and the settings'
	// revision come in the environment, out of the host's process listing.
	if connections.RunCloudOCR(ctx, os.Getenv("JPACK_OCR_CONNECTION"), os.Getenv("JPACK_OCR_REVISION"), os.Args[1:], os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
