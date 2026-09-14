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
	"syscall"
)

const mcpUsage = "usage: gateway mcp --config <engine.json> (--http | --stdio)"

func cmdMCP(args []string) int {
	return runMCP(args, os.Stderr, osMCPReachHost())
}

// runMCP is the command with its diagnostics stream and its view of the
// host given, so a test reads what a refusal says.
func runMCP(args []string, stderr io.Writer, reach mcpReachHost) int {
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
	server, err := newMCPServer(cfg, bindings, identity)
	if err != nil {
		fmt.Fprintln(stderr, "start:", err)
		return 1
	}
	server.log = stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server.operatorControls(ctx)
	if transport == "--stdio" {
		if err := server.serveStdio(ctx, os.Stdin, os.Stdout, os.Getenv(mcpTokenEnv)); err != nil {
			fmt.Fprintln(stderr, "mcp:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "mcp on http://%s%s (authority %s, %d tools, signer at %s)\n", cfg.mcp.listen, mcpEndpoint, cfg.authority, len(server.order), cfg.listen)
	if err := server.listenHTTP(ctx); err != nil {
		fmt.Fprintln(stderr, "mcp:", err)
		return 1
	}
	return 0
}
