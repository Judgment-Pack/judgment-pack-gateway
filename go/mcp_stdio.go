package main

// The stdio transport of the MCP server: newline-delimited JSON-RPC on
// stdin and stdout, nothing but protocol on stdout, one transport session
// for the life of the process, and the token given once at start. Each
// line is admitted in the reader's own turn -- the lifecycle, the session
// it resolves to, the window and the gate, in arrival order -- and what
// passes is run as it is admitted, up to a bound of work outstanding, past
// which the reader waits; each answer is written whole, and the first
// answer that cannot be written ends the transport.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// mcpTokenEnv is where a host hands the stdio server its principal's
// token, as MCP hosts hand every server its secrets.
const mcpTokenEnv = "ENGINE_TOKEN"

// mcpStdioBacklog bounds the messages admitted and not yet answered over
// stdio: a host that writes faster than its answers are read finds the
// reader waiting, not the process growing.
const mcpStdioBacklog = 64

// serveStdio runs the transport over the given streams under one token,
// verified once at start when the engine has an identity and not sent at
// all when it has none. It returns when the input ends and every answer
// is written, when an answer cannot be written, or when the context ends
// -- at once, whatever is blocked on the streams, which the process's end
// releases.
func (s *mcpServer) serveStdio(ctx context.Context, in io.Reader, out io.Writer, token string) error {
	if s.identity == nil {
		// no identity: the signer records caller null, and no token is sent,
		// whatever the environment held
		token = ""
	} else if err := s.verifyBearer(token); err != nil {
		return fmt.Errorf("%s: %v", mcpTokenEnv, err)
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	sess := s.newSession()
	// answers are written one at a time; the first failure is kept apart
	// from that lock, so ending never waits on a write stuck on the output
	var writes, failures sync.Mutex
	var failed error // the first answer that could not be written
	firstFailure := func() error {
		failures.Lock()
		defer failures.Unlock()
		return failed
	}
	write := func(line []byte) {
		if firstFailure() != nil {
			return
		}
		writes.Lock()
		defer writes.Unlock()
		if firstFailure() != nil {
			return
		}
		if _, err := out.Write(append(append([]byte(nil), line...), '\n')); err != nil {
			failures.Lock()
			if failed == nil {
				failed = err
			}
			failures.Unlock()
			stop()
		}
	}
	outstanding := make(chan struct{}, s.stdioBacklog)
	var handlers sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 0, 64*1024), mcpMaxMessageBytes+1)
		for scanner.Scan() {
			if ctx.Err() != nil {
				// ended: nothing more is admitted
				handlers.Wait()
				done <- nil
				return
			}
			line := append([]byte(nil), scanner.Bytes()...)
			if len(line) == 0 {
				continue
			}
			arrived := s.now()
			// admitted here, in order; run wherever, within the bound
			outcome := s.admit(sess, token, arrived, line)
			if outcome.run == nil {
				if outcome.response != nil {
					write(outcome.response)
				}
				continue
			}
			select {
			case outstanding <- struct{}{}:
			case <-ctx.Done():
				handlers.Wait()
				done <- nil
				return
			}
			if ctx.Err() != nil {
				<-outstanding
				handlers.Wait()
				done <- nil
				return
			}
			handlers.Add(1)
			go func(run func(context.Context) mcpOutcome) {
				defer handlers.Done()
				defer func() { <-outstanding }()
				if outcome := run(ctx); outcome.response != nil {
					write(outcome.response)
				}
			}(outcome.run)
		}
		err := scanner.Err()
		if errors.Is(err, bufio.ErrTooLong) {
			write(rpcFailure(nil, jsonrpcError{rpcInvalidRequest, "a message exceeds the bound"}))
		}
		handlers.Wait()
		done <- err
	}()
	select {
	case <-ctx.Done():
		if err := firstFailure(); err != nil {
			return fmt.Errorf("an answer could not be written: %s", transportErrorCategory(err))
		}
		return nil
	case err := <-done:
		if failure := firstFailure(); failure != nil {
			return fmt.Errorf("an answer could not be written: %s", transportErrorCategory(failure))
		}
		return err
	}
}

var _ = time.Now
