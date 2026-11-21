// FortiTatake: an intensive study engine for Fortinet PS interviews and certs.
// See docs/BLUEPRINT.md.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/jose00735/fortitatake/internal/server"
	"github.com/jose00735/fortitatake/internal/store"
)

var version = "v0.1.0"

//go:embed web
var webFS embed.FS

func main() {
	browser := flag.Bool("browser", false, "open in the default browser instead of the FortiTatake window")
	port := flag.String("port", "0", "local port to listen on (0 = any free port)")
	dir := flag.String("data", store.DefaultDir(), "folder for your progress log")
	noOpen := flag.Bool("no-open", false, "only print the address (for development)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("FortiTatake", version)
		return
	}
	st, err := store.Open(*dir)
	if err != nil {
		fatal("could not open the data folder %s: %v", *dir, err)
	}
	ui, _ := fs.Sub(webFS, "web")
	srv := server.New(st, ui, version)
	url, err := srv.Listen(*port)
	if err != nil {
		fatal("could not start the local server: %v", err)
	}
	go func() {
		if err := srv.Serve(); err != nil {
			log.Println("server stopped:", err)
		}
	}()
	if *noOpen {
		fmt.Println("FortiTatake", version, "listening on", url)
		select {}
	}
	run(srv, url, *browser)
}

func fatal(format string, a ...any) {
	showError(fmt.Sprintf(format, a...))
	os.Exit(1)
}
