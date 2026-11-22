//go:build !windows

package winfw

// Check reports that firewall management isn't needed on this platform.
func Check(port int) Status { return Status{} }

// Fix is a no-op outside Windows.
func Fix(port int) error { return nil }
