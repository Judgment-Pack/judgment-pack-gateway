package main

// The MCP server's check of its own reach at start (docs/design/mcp-server.md,
// "What it is"): it runs as the frontend's user and group and no other,
// holds no capability, belongs to no supplementary group but its own, and
// is denied the seed, every credentials file and the store. A path that
// does not exist, or any answer other than denial, is refused too, since it
// says nothing.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
)

// mcpReachHost is what the check asks the operating system; tests stand
// each in.
type mcpReachHost struct {
	euid   int
	gid    int
	groups func() ([]int, error)
	caps   func() (empty bool, reason string)
	open   func(path string) error
}

func osMCPReachHost() mcpReachHost {
	return mcpReachHost{
		euid:   os.Geteuid(),
		gid:    os.Getegid(),
		groups: os.Getgroups,
		caps:   capabilitySetsEmpty,
		open: func(path string) error {
			f, err := os.Open(path)
			if err == nil {
				f.Close()
			}
			return err
		},
	}
}

// mcpReachCheck refuses to run a process that could reach what this one
// must not.
func mcpReachCheck(cfg engineConfig, host mcpReachHost) error {
	if host.euid == 0 {
		return errors.New("the MCP server runs as root; it runs as its own unprivileged user (engine-mcp)")
	}
	if host.euid != frontendUID {
		return fmt.Errorf("the MCP server runs as uid %d; it runs as %s (uid %d), the user the image's paths are closed to", host.euid, frontendUser, frontendUID)
	}
	if host.gid != frontendUID {
		return fmt.Errorf("the MCP server runs as gid %d; it runs in %s's own group (gid %d)", host.gid, frontendUser, frontendUID)
	}
	if empty, reason := host.caps(); !empty {
		return errors.New("the MCP server holds a capability: " + reason + "; it runs with every capability set empty")
	}
	groups, err := host.groups()
	if err != nil {
		return fmt.Errorf("the MCP server cannot read its groups: %v", err)
	}
	// a container runtime lists the primary group in the supplementary
	// set; that membership admits nothing the gid does not, and any other
	// would
	for _, g := range groups {
		if g != host.gid {
			return fmt.Errorf("the MCP server is in supplementary group %d; it runs in its own group and no other", g)
		}
	}
	paths := map[string]string{"the seed": cfg.seed, "the store": cfg.store}
	for _, p := range cfg.platforms {
		ops := make([]string, 0, len(p.credentials))
		for op := range p.credentials {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			paths[fmt.Sprintf("platform %s's %s credentials", p.name, op)] = p.credentials[op]
		}
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err := host.open(paths[name])
		switch {
		case err == nil:
			return fmt.Errorf("the MCP server can open %s (%s); it must be denied", name, paths[name])
		case errors.Is(err, fs.ErrPermission):
		default:
			return fmt.Errorf("opening %s (%s) answered %v, not a denial; the deployment is not in place", name, paths[name], err)
		}
	}
	return nil
}
