//go:build !linux && !darwin

package connections

import "os"

const noFollow = 0
const nonBlock = 0

func private(os.FileInfo, bool) error { return ErrStorage }
func lock(*os.File) error             { return ErrStorage }
func unlock(*os.File)                 {}
