package ftkos

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

func httpGetSmall(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

// download fetches url to dst through dst.part, resuming an interrupted download,
// and shows progress on the OS screen.
func (m *Manager) download(ctx context.Context, url, dst string) error {
	part := dst + ".part"
	var have int64
	if st, err := os.Stat(part); err == nil {
		have = st.Size()
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if have > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(have, 10)+"-")
	}
	resp, err := (&http.Client{Timeout: 2 * time.Hour}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	switch resp.StatusCode {
	case 206:
	case 200:
		flag, have = os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0
	default:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	total := have + resp.ContentLength
	f, err := os.OpenFile(part, flag, 0644)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	last := time.Time{}
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return err
			}
			have += int64(n)
			if time.Since(last) > 500*time.Millisecond {
				last = time.Now()
				m.emit("step", map[string]any{"label": fmt.Sprintf("Downloading Ubuntu 24.04 for WSL: %d of %d MB", have>>20, total>>20), "done": have, "total": total})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return fmt.Errorf("interrupted at %d MB; press Set up again to resume (%v)", have>>20, rerr)
		}
	}
	f.Close()
	return os.Rename(part, dst)
}
