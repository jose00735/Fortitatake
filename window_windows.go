//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/jchv/go-webview2"

	"github.com/jose00735/fortitatake/internal/server"
)

var (
	user32         = syscall.NewLazyDLL("user32.dll")
	procMessageBox = user32.NewProc("MessageBoxW")
)

func run(srv *server.Server, url string, browser bool) {
	if !browser {
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			Debug:     os.Getenv("FORTITATAKE_DEBUG") != "",
			AutoFocus: true,
			WindowOptions: webview2.WindowOptions{
				Title:  "FortiTatake",
				Width:  1280,
				Height: 840,
				Center: true,
			},
		})
		if w != nil {
			srv.Native = true
			srv.Quit = func() { w.Dispatch(func() { w.Terminate() }) }
			w.SetSize(900, 600, webview2.HintMin)
			w.Navigate(url)
			w.Run()
			w.Destroy()
			return
		}
		showError("FortiTatake could not open its window because the Microsoft Edge WebView2 runtime is missing.\n\nIt will open in your browser instead. To get the window, install WebView2 from microsoft.com/edge/webview2.")
	}
	quit := make(chan struct{})
	srv.Quit = func() { close(quit) }
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	<-quit
}

func showError(msg string) {
	t, _ := syscall.UTF16PtrFromString("FortiTatake")
	m, _ := syscall.UTF16PtrFromString(msg)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x30)
}
