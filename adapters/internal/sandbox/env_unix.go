//go:build !windows

package sandbox

func envKey(name string) string { return name }
