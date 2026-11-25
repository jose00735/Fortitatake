//go:build !windows

package ftkos

import "errors"

func canBuild() bool { return false }

func (m *Manager) builderInfo() map[string]any { return nil }

func (m *Manager) setupJob(*job) error {
	return errors.New("FortiTatake OS is built on the PC; it arrives on this device by sync")
}

func (m *Manager) buildJob(*job, string, string) error {
	return errors.New("FortiTatake OS is built on the PC; it arrives on this device by sync")
}
