package main

// gateway mcp --config <engine.json> --http | --stdio: the MCP server, run
// from the unprivileged copy of this executable as the frontend's user
// (docs/design/mcp-server.md, "What it is").

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const mcpUsage = "usage: gateway mcp --config <engine.json> (--http | --stdio)"

func cmdMCP(args []string) int {
	var config, transport string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) || config != "" {
				fmt.Fprintln(os.Stderr, mcpUsage)
				return 2
			}
			config = args[i+1]
			i++
		case "--http", "--stdio":
			if transport != "" {
				fmt.Fprintln(os.Stderr, mcpUsage)
				return 2
			}
			transport = args[i]
		default:
			fmt.Fprintln(os.Stderr, mcpUsage)
			return 2
		}
	}
	if config == "" || transport == "" {
		fmt.Fprintln(os.Stderr, mcpUsage)
		return 2
	}
	host := osEngineHost()
	cfg, bindings, err := loadEngineConfig(config, host.account)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if cfg.mcp == nil {
		fmt.Fprintln(os.Stderr, "start: the configuration has no mcp member (docs/design/mcp-server.md)")
		return 1
	}
	if transport == "--http" {
		// no unprotected HTTP mode: the resource and an identity are what
		// the transport's authorization is made of
		if cfg.mcp.resource == "" {
			fmt.Fprintln(os.Stderr, "start: --http needs mcp.resource, the URL this server is reached as")
			return 1
		}
		if cfg.identity == nil {
			fmt.Fprintln(os.Stderr, "start: --http needs an identity; there is no unprotected HTTP mode")
			return 1
		}
		if err := validIssuerURL(cfg.identity.issuer); err != nil {
			fmt.Fprintln(os.Stderr, "start: identity.issuer:", err)
			return 1
		}
	}
	identity, err := loadIdentity(cfg.identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := mcpReachCheck(cfg, osMCPReachHost()); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	server, err := newMCPServer(cfg, bindings, identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if transport == "--stdio" {
		if err := server.serveStdio(ctx, os.Stdin, os.Stdout, os.Getenv(mcpTokenEnv)); err != nil {
			fmt.Fprintln(os.Stderr, "mcp:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "mcp on http://%s%s (authority %s, %d tools, signer at %s)\n", cfg.mcp.listen, mcpEndpoint, cfg.authority, len(server.order), cfg.listen)
	if err := server.listenHTTP(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}
