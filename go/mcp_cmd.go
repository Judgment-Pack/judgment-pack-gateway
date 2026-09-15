package main

// gateway mcp --config <engine.json> --http | --stdio: the MCP server, run
// from the unprivileged copy of this executable as the frontend's user
// (docs/design/mcp-server.md, "What it is").

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const mcpUsage = "usage: gateway mcp --config <engine.json> (--http | --stdio)"

func cmdMCP(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runMCP(ctx, args, os.Stdin, os.Stdout, os.Stderr, osMCPReachHost())
}

// runMCP is the command with its context, its streams and its view of the
// host given, so a test reads what a refusal says and runs the serving
// paths with a stderr that never drains. A refusal to start is written
// before anything is served, and reads the configuration back to the
// operator who started the process; once serving, everything the process
// says goes through its diagnostics stream, which nothing waits for, and
// what it says as it ends is flushed for at most a second.
func runMCP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, reach mcpReachHost) int {
	var config, transport string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) || config != "" {
				fmt.Fprintln(stderr, mcpUsage)
				return 2
			}
			config = args[i+1]
			i++
		case "--http", "--stdio":
			if transport != "" {
				fmt.Fprintln(stderr, mcpUsage)
				return 2
			}
			transport = args[i]
		default:
			fmt.Fprintln(stderr, mcpUsage)
			return 2
		}
	}
	if config == "" || transport == "" {
		fmt.Fprintln(stderr, mcpUsage)
		return 2
	}
	host := osEngineHost()
	cfg, bindings, err := loadEngineConfig(config, host.account)
	if err != nil {
		fmt.Fprintln(stderr, "start:", err)
		return 1
	}
	if cfg.mcp == nil {
		fmt.Fprintln(stderr, "start: the configuration has no mcp member (docs/design/mcp-server.md)")
		return 1
	}
	if transport == "--http" {
		// no unprotected HTTP mode: the resource and an identity are what
		// the transport's authorization is made of
		if cfg.mcp.resource == "" {
			fmt.Fprintln(stderr, "start: --http needs mcp.resource, the URL this server is reached as")
			return 1
		}
		if cfg.identity == nil {
			fmt.Fprintln(stderr, "start: --http needs an identity; there is no unprotected HTTP mode")
			return 1
		}
		if err := validIssuerURL(cfg.identity.issuer); err != nil {
			fmt.Fprintln(stderr, "start: identity.issuer:", err)
			return 1
		}
	}
	identity, err := loadIdentity(cfg.identity)
	if err != nil {
		fmt.Fprintln(stderr, "start:", err)
		return 1
	}
	if err := mcpReachCheck(cfg, reach); err != nil {
		fmt.Fprintln(stderr, "start:", err)
		return 1
	}
	server, err := newMCPServer(cfg, bindings, identity, config)
	if err != nil {
		fmt.Fprintln(stderr, "start:", err)
		return 1
	}
	server.log = stderr
	if len(server.dropped) > 0 {
		server.reports.controlf("mcp: the tool listing would pass %d bytes; the snapshots of %s are not served, and their tools are described as if nothing were captured", listingBound, strings.Join(server.dropped, ", "))
	}
	defer server.reports.flush(time.Second)
	server.operatorControls(ctx)
	if transport == "--stdio" {
		if err := server.serveStdio(ctx, stdin, stdout, os.Getenv(mcpTokenEnv)); err != nil {
			server.reports.controlf("mcp: %v", err)
			return 1
		}
		return 0
	}
	// the diagnostics stream names no address: a host may forward it
	// anywhere
	server.reports.controlf("mcp: serving --http at the configured address (authority %s, %d tools)", cfg.authority, len(server.order))
	if err := server.listenHTTP(ctx); err != nil {
		server.reports.controlf("mcp: the transport ended: %s", transportErrorCategory(err))
		return 1
	}
	return 0
}
