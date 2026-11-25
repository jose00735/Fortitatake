//go:build windows

package main

import (
	"embed"
	"io/fs"
)

// The PC builds FortiTatake OS, so it carries the build tree, the driver and the agents.
//
//go:embed ftkos/buildroot-external ftkos/builder ftkos/bin
var ftkosAssets embed.FS

func engineAssets() fs.FS { return ftkosAssets }
