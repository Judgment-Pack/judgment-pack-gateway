package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// sandboxAtStart is measureSandboxAtStart (engineVersion 23;
// docs/design/engine-config.md, "Measuring the sandbox at the start";
// docs/adr/0030-the-engine-image-carries-the-sandbox-launcher.md). With the
// member on, the start probes every source's sandbox as the source's user,
// one source at a time, each under a launch's own budget
// (sandboxLaunchProbeTimeout), and refuses to start where a launch of the
// source would be refused (sandboxSourceCommand): a probe that gives no
// report, or one that measures a restricted mode as not enforced. Every
// such source is named, with the probe's reason. A completed probe is kept
// for the source, so each launch after the start is bound to the posture
// the start measured. A source the configuration does not wrap is refused
// too: under engineVersion 13 and later every source is wrapped, and the
// member promises a measurement of each.
//
// With the member off nothing is probed and nothing is said: each launch
// probes and refuses as it did. The line returned is what the start prints.
func sandboxAtStart(cfg engineConfig, sources map[string]sourceSpec) (string, error) {
	if !cfg.measureSandboxAtStart {
		return "", nil
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	var measured, refused []string
	for _, name := range names {
		spec := sources[name]
		if spec.sandbox == nil {
			refused = append(refused, fmt.Sprintf("source %s: the configuration does not select the adapter sandbox wrapper for it", name))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), sandboxLaunchProbeTimeout)
		report, err := sandboxPostureProbe(ctx, spec)
		cancel()
		if err != nil {
			refused = append(refused, fmt.Sprintf("source %s: its sandbox check as its user gave no report: %s", name, pathless(err)))
			continue
		}
		p := report.Protection
		if p.Mode != "danger-full-access" && p.State == postureNotEnforced {
			refused = append(refused, fmt.Sprintf("source %s: %s is not enforced under %s: %s", name, p.Mode, p.Backend, p.Reason))
			continue
		}
		measured = append(measured, fmt.Sprintf("%s %s %s %s", name, p.Mode, p.Backend, p.State))
	}
	if len(refused) > 0 {
		return "", fmt.Errorf("measureSandboxAtStart: %s; the engine does not start (gateway posture --config, given this configuration, reports each source)", strings.Join(refused, "; "))
	}
	if len(measured) == 0 {
		return "measureSandboxAtStart: the configuration has no source to measure", nil
	}
	return "measureSandboxAtStart: measured " + strings.Join(measured, ", "), nil
}
