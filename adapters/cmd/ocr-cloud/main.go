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
	if connections.RunCloudOCR(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
}
