package main

// The stdio transport of the MCP server: newline-delimited JSON-RPC on
// stdin and stdout, nothing but protocol on stdout, one transport session
// for the life of the process, and the token given once at start. Lines
// are read as they arrive and handled as they are read, so a call behind
// a slow forward is counted in the window it arrived in and the bounds,
// not the pipe, say how many run at once; each answer is written whole.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// mcpTokenEnv is where a host hands the stdio server its principal's
// token, as MCP hosts hand every server its secrets.
const mcpTokenEnv = "ENGINE_TOKEN"

// serveStdio runs the transport over the given streams under one token,
// verified once at start when the engine has an identity and not sent at
// all when it has none. An initialize is handled in the reader's own turn,
// so a host that writes its first call behind the initialize without
// waiting finds the session initialized; every other message is handled
// as it is read. It returns when the input ends and every answer is
// written, or when the context ends -- at once, whatever is blocked on the
// streams, which the process's end releases.
func (s *mcpServer) serveStdio(ctx context.Context, in io.Reader, out io.Writer, token string) error {
	if s.identity == nil {
		// no identity: the signer records caller null, and no token is sent,
		// whatever the environment held
		token = ""
	} else if err := s.verifyBearer(token); err != nil {
		return fmt.Errorf("%s: %v", mcpTokenEnv, err)
	}
	sess := s.newSession()
	var writes sync.Mutex
	write := func(line []byte) error {
		writes.Lock()
		defer writes.Unlock()
		_, err := out.Write(append(append([]byte(nil), line...), '\n'))
		return err
	}
	var handlers sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 0, 64*1024), mcpMaxMessageBytes+1)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if len(line) == 0 {
				continue
			}
			arrived := s.now()
			if req, perr := parseMCPMessage(line); perr == nil && req.method == "initialize" {
				if outcome := s.handle(ctx, sess, token, arrived, line); outcome.response != nil {
					_ = write(outcome.response)
				}
				continue
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				if outcome := s.handle(ctx, sess, token, arrived, line); outcome.response != nil {
					_ = write(outcome.response)
				}
			}()
		}
		err := scanner.Err()
		if errors.Is(err, bufio.ErrTooLong) {
			_ = write(rpcFailure(nil, jsonrpcError{rpcInvalidRequest, "a message exceeds the bound"}))
		}
		handlers.Wait()
		done <- err
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-done:
		return err
	}
}
