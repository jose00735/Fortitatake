package ftkos

import (
	"context"
	"os"
	"testing"
	"time"
)

// FTK_TEST_DATA=<dir containing ftkos/builds/x86_64-generic with kernel, rootfs.erofs, build-info.json>
func TestBootHello(t *testing.T) {
	dir := os.Getenv("FTK_TEST_DATA")
	if dir == "" {
		t.Skip("FTK_TEST_DATA not set")
	}
	m := New(dir, nil, "test")
	if _, err := m.seal(m.Dir + "/builds/x86_64-generic"); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	vm, err := m.Boot(context.Background(), 128)
	if err != nil {
		t.Fatal(err)
	}
	defer vm.Stop()
	res, err := vm.Call(map[string]any{"op": "hello"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("accel=%s boot=%v rss=%dMB hello=%v", vm.Accel, time.Since(t0), vm.RSS()>>20, res)
}
