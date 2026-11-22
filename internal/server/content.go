package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jose00735/fortitatake/internal/ftsp"
)

// Content serves the study content bundle. The copy embedded in the app can be
// overridden by a newer bundle in <data>/content/bundle.json, which is how new
// modules reach a phone over sync (or a PC without rebuilding the app).
type Content struct {
	mu   sync.Mutex
	dir  string
	data []byte
	pack ftsp.Pack
}

func bundleVersion(b []byte) (string, error) {
	var v struct {
		Version string            `json:"version"`
		Modules []json.RawMessage `json:"modules"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	if v.Version == "" || len(v.Modules) == 0 {
		return "", errors.New("not a FortiTatake content bundle")
	}
	return v.Version, nil
}

func packOf(b []byte, version string) ftsp.Pack {
	h := sha256.Sum256(b)
	return ftsp.Pack{ID: "bundle", Version: version, SHA256: strings.ToUpper(hex.EncodeToString(h[:])), Size: len(b)}
}

// NewContent picks the newer of the embedded bundle and the one in dataDir.
func NewContent(ui fs.FS, dataDir string) *Content {
	c := &Content{dir: filepath.Join(dataDir, "content")}
	if b, err := fs.ReadFile(ui, "content/bundle.json"); err == nil {
		if v, err := bundleVersion(b); err == nil {
			c.data, c.pack = b, packOf(b, v)
		}
	}
	if b, err := os.ReadFile(filepath.Join(c.dir, "bundle.json")); err == nil {
		if v, err := bundleVersion(b); err == nil && v >= c.pack.Version {
			c.data, c.pack = b, packOf(b, v)
		}
	}
	return c
}

// Current returns the bundle in use.
func (c *Content) Current() ([]byte, ftsp.Pack) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data, c.pack
}

// Install saves a bundle received from the hub and starts serving it.
func (c *Content) Install(b []byte, p ftsp.Pack) error {
	v, err := bundleVersion(b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(c.dir, "bundle.json")
	if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	c.mu.Lock()
	c.data, c.pack = b, packOf(b, v)
	c.mu.Unlock()
	return nil
}
