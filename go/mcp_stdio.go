package main

// The stdio transport of the MCP server: newline-delimited JSON-RPC on
// stdin and stdout, nothing but protocol on stdout, one transport session
// for the life of the process, and the token given once at start.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
)

// mcpTokenEnv is where a host hands the stdio server its principal's
// token, as MCP hosts hand every server its secrets.
const mcpTokenEnv = "ENGINE_TOKEN"

// serveStdio runs the transport over the given streams under one token,
// verified once at start when the engine has an identity.
func (s *mcpServer) serveStdio(ctx context.Context, in io.Reader, out io.Writer, token string) error {
	if err := s.verifyBearer(token); err != nil {
		return fmt.Errorf("%s: %v", mcpTokenEnv, err)
	}
	sess := s.newSession()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), mcpMaxMessageBytes+1)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		outcome := s.handle(ctx, sess, token, line)
		if outcome.response == nil {
			continue
		}
		if _, err := out.Write(append(append([]byte(nil), outcome.response...), '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			_, _ = out.Write(append(rpcFailure(nil, jsonrpcError{rpcInvalidRequest, "a message exceeds the bound"}), '\n'))
		}
		return err
	}
	return nil
}
