//go:build !windows

package main

import "io/fs"

func engineAssets() fs.FS { return nil }
