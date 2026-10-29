package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type engineSandbox struct {
	policy     string
	workspaces map[string]string
}

type sourceSandbox struct {
	probe                             *sourceSandboxProbe
	helper, policy, workspace, source string
	classes                           []string
}

type sourceSandboxProbe struct {
	mu     sync.Mutex
	done   bool
	report sandboxProbeReport
}

func parseEngineSandbox(value value) (*engineSandbox, error) {
	obj, err := requireObject(value, "sandbox")
	if err != nil {
		return nil, err
	}
	if err = exactlyMembers(obj, map[string]bool{"policy": false, "workspaces": false}, "sandbox"); err != nil {
		return nil, err
	}
	s := &engineSandbox{workspaces: map[string]string{}}
	if _, present := obj.get("policy"); present {
		if s.policy, err = requireAbsolutePath(obj, "policy"); err != nil {
			return nil, err
		}
	}
	if raw, present := obj.get("workspaces"); present {
		workspaces, err := requireObject(raw, "sandbox.workspaces")
		if err != nil {
			return nil, err
		}
		for name := range workspaces.byName {
			if name == "" {
				return nil, errors.New("sandbox-policy-invalid: empty source selector")
			}
			path, err := requireAbsolutePath(workspaces, name)
			if err != nil {
				return nil, err
			}
			s.workspaces[name] = path
		}
	}
	return s, nil
}

func validateEngineSandbox(cfg engineConfig, bindings map[string]binding) error {
	if cfg.sandbox == nil {
		return nil
	}
	sources := deriveSources(cfg, bindings)
	for name := range cfg.sandbox.workspaces {
		if _, ok := sources[name]; !ok {
			return errors.New("sandbox-policy-invalid: workspace selector names no enabled source")
		}
	}
	for name := range sources {
		platform, opName, _ := strings.Cut(name, "/")
		b := bindings[platform]
		var op *operation
		switch opName {
		case "live":
			op = b.live
		case "write":
			op = b.write
		}
		if op == nil || len(op.command) == 0 {
			continue
		}
		if workspace := cfg.sandbox.workspaces[name]; workspace != "" && filepath.Clean(workspace) != filepath.Clean(op.workspace) {
			return errors.New("sandbox-policy-invalid: customer and adapter workspaces differ")
		}
		if cfg.sandbox.policy != "" && op.sandboxPolicy != "" && filepath.Clean(cfg.sandbox.policy) != filepath.Clean(op.sandboxPolicy) {
			return errors.New("sandbox-policy-invalid: customer and adapter policies differ")
		}
	}
	return nil
}

// sandboxSourceCommand wraps the already-resolved original executable. Receipt
// identity remains the original adapter's digest. The source user switch and
// declared environment are applied to this wrapper by the existing launcher.
func sandboxSourceCommand(ctx context.Context, spec sourceSpec, path string, argv []string) (*exec.Cmd, error) {
	if spec.sandbox == nil {
		cmd := exec.CommandContext(ctx, path, argv[1:]...)
		cmd.Args = argv
		return cmd, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	s := spec.sandbox
	helper, err := exec.LookPath(s.helper)
	if err != nil {
		return nil, fmt.Errorf("sandbox-not-enforced: source sandbox helper unavailable: %w", err)
	}
	args := []string{"run", "--policy=" + s.policy, "--source=" + s.source, "--workspace=" + s.workspace, "--", absolute}
	args = append(args, argv[1:]...)
	return exec.CommandContext(ctx, helper, args...), nil
}
