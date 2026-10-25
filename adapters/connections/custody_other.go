//go:build !linux && !darwin

package connections

import "os"

func lock(*os.File) error { return ErrStorage }
func unlock(*os.File)     {}
