//go:build !windows

package sandbox

import (
	"bytes"
	"io"
	"os"
)

// readEnv reads the NUL-terminated KEY=VALUE items a launcher was handed on
// descriptor fd, and closes it.
func readEnv(fd int) ([]string, error) {
	f := os.NewFile(uintptr(fd), "environment")
	if f == nil {
		return nil, os.ErrInvalid
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil, err
	}
	env := []string{}
	for _, item := range bytes.Split(data, []byte{0}) {
		if len(item) > 0 {
			env = append(env, string(item))
		}
	}
	return env, nil
}
