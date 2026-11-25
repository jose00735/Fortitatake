package ftkos

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Arm core part numbers (MIDR, as /proc/cpuinfo prints them) to GCC -mcpu names.
var armParts = map[string]string{
	"0xd03": "cortex-a53", "0xd05": "cortex-a55", "0xd0a": "cortex-a75", "0xd0b": "cortex-a76",
	"0xd0d": "cortex-a77", "0xd41": "cortex-a78", "0xd44": "cortex-x1", "0xd46": "cortex-a510",
	"0xd47": "cortex-a710", "0xd48": "cortex-x2", "0xd4d": "cortex-a715", "0xd4e": "cortex-x3",
	"0xd80": "cortex-a520", "0xd81": "cortex-a720", "0xd82": "cortex-x4", "0xd85": "cortex-x925",
	"0xd87": "cortex-a725",
}

// phoneTuning reads the phone's CPU report (saved when the phone syncs its test results)
// and returns flags for its cores. Mixed clusters get the march of the smallest core and
// a tune for the most common one, so every core can run the code.
func (m *Manager) phoneTuning() (string, error) {
	b, err := os.ReadFile(filepath.Join(m.Dir, "phone-device.json"))
	if err != nil {
		return "", errors.New("run the stage 0 test on the phone and sync once, so the PC knows its CPU")
	}
	var d struct {
		CPUParts map[string]int `json:"cpu_parts"`
		Features string         `json:"features"`
	}
	json.Unmarshal(b, &d)
	type pc struct {
		name string
		n    int
	}
	var cores []pc
	for part, n := range d.CPUParts {
		if name, ok := armParts[strings.ToLower(part)]; ok {
			cores = append(cores, pc{name, n})
		}
	}
	if len(cores) == 0 {
		return "", errors.New("the phone's CPU cores aren't in FortiTatake's table yet; use the generic build")
	}
	sort.Slice(cores, func(i, j int) bool { return cores[i].n > cores[j].n })
	march := "armv8.2-a"
	f := " " + d.Features + " "
	switch {
	case strings.Contains(f, " sve2 ") && strings.Contains(f, " bf16 "):
		march = "armv9-a"
	case strings.Contains(f, " dotprod ") && strings.Contains(f, " lrcpc "):
		march = "armv8.2-a+dotprod+rcpc"
	}
	return "-march=" + march + " -mtune=" + cores[0].name, nil
}
