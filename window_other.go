//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/jose00735/fortitatake/internal/server"
)

// On Linux and macOS FortiTatake runs in the default browser (useful for development).
func run(srv *server.Server, url string, _ bool) {
	quit := make(chan struct{})
	srv.Quit = func() { close(quit) }
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	if err := exec.Command(opener, url).Start(); err != nil {
		fmt.Println("Open this address in your browser:", url)
	}
	fmt.Println("FortiTatake is running. Quit from the app or with Ctrl+C.")
	<-quit
}

func showError(msg string) { fmt.Fprintln(os.Stderr, "FortiTatake:", msg) }
