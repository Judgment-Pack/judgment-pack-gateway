package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
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
	// Every configured workspace and every effective policy file: a policy
	// must lie outside all of them, not only its own source's, or a source
	// confined to its workspace could rewrite another source's policy.
	var workspaces, policies []string
	if cfg.sandbox.policy != "" {
		policies = append(policies, cfg.sandbox.policy)
	}
	for _, workspace := range cfg.sandbox.workspaces {
		workspaces = append(workspaces, workspace)
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
		if op.workspace != "" {
			workspaces = append(workspaces, op.workspace)
		}
		if cfg.sandbox.policy == "" && op.sandboxPolicy != "" {
			policies = append(policies, op.sandboxPolicy)
		}
	}
	for _, policy := range policies {
		for _, workspace := range workspaces {
			if pathWithin(policy, workspace) {
				return fmt.Errorf("sandbox-policy-invalid: policy %s lies inside the source workspace %s; a policy must lie outside every configured workspace", policy, workspace)
			}
		}
	}
	// Every source is wrapped: a loader variable in a platform's environment
	// would choose code for the source's adapter, whatever its kind.
	for _, p := range cfg.platforms {
		wrapped := false
		for name := range sources {
			wrapped = wrapped || strings.HasPrefix(name, p.name+"/")
		}
		if !wrapped {
			continue
		}
		for _, pair := range p.environment {
			if name, _, _ := strings.Cut(pair, "="); loaderVariable(name) {
				return fmt.Errorf("platform %s: sandbox-loader-variable-refused: environment.%s is a dynamic-loader variable (LD_*, DYLD_* or GCONV_PATH), which a source run through the sandbox wrapper may not carry", p.name, name)
			}
		}
	}
	return nil
}

// pathWithin reports whether path is dir or lies below it, compared as
// written and, where both resolve, as resolved.
func pathWithin(path, dir string) bool {
	within := func(path, dir string) bool {
		rel, err := filepath.Rel(dir, path)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	}
	if within(filepath.Clean(path), filepath.Clean(dir)) {
		return true
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	// The policy itself may not exist yet; its directory decides.
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		parent, perr := filepath.EvalSymlinks(filepath.Dir(path))
		if perr != nil {
			return false
		}
		resolvedPath = filepath.Join(parent, filepath.Base(path))
	}
	return within(resolvedPath, resolvedDir)
}

// runtimeSockets reports whether this source runs a container runtime client,
// which needs the runtime's socket: its launch and probe keep known runtime
// sockets reachable, and both report partial.
func (s *sourceSandbox) runtimeSockets() bool { return slices.Contains(s.classes, "container-helper") }

// sandboxHelperArgs is the helper's selection for verb, "probe" or "run":
// one place, so the probe measures exactly what the launch will use.
func sandboxHelperArgs(s *sourceSandbox, verb string) []string {
	args := []string{verb, "--policy=" + s.policy, "--source=" + s.source, "--workspace=" + s.workspace}
	if s.runtimeSockets() {
		args = append(args, "--container-runtime")
	}
	return args
}

// sandboxLaunchProbeTimeout bounds the posture probe a launch waits for.
const sandboxLaunchProbeTimeout = 12 * time.Second

// sandboxSourceCommand wraps the already-resolved original executable. Receipt
// identity remains the original adapter's digest. The source user switch and
// declared environment are applied to this wrapper by the existing launcher.
//
// The launch is bound to the posture reported for the source: the cached
// probe (taken now if none completed yet) supplies the mode, backend and
// policy digest, and the helper refuses to run under any other. A changed
// policy, or a backend that fails at launch, refuses; nothing falls back.
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
	// Held at start (holdAdapterSources), never looked up on PATH here.
	if !filepath.IsAbs(s.helper) {
		return nil, fmt.Errorf("sandbox-not-enforced: source sandbox helper %s was not held at start", s.helper)
	}
	probeCtx, cancel := context.WithTimeout(ctx, sandboxLaunchProbeTimeout)
	report, err := sandboxPostureProbe(probeCtx, spec)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("sandbox-not-enforced: the source's sandbox posture could not be measured before its launch: %v", err)
	}
	p := report.Protection
	args := append(sandboxHelperArgs(s, "run"), "--expect-mode="+p.Mode, "--expect-backend="+p.Backend, "--expect-policy="+report.PolicyDigest, "--", absolute)
	args = append(args, argv[1:]...)
	return exec.CommandContext(ctx, s.helper, args...), nil
}
