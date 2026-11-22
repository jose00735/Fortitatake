// Package winfw checks and fixes the Windows Firewall so phones on the LAN can reach
// the FortiTatake sync hub. On other platforms it reports "not supported".
package winfw

// Status is what the Settings page shows about the firewall.
type Status struct {
	Supported bool     `json:"supported"`
	Profiles  []string `json:"profiles"` // network categories of connected networks: Private, Public, DomainAuthenticated
	RuleOK    bool     `json:"rule_ok"`  // our inbound rules exist
	Port      int      `json:"port,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// RuleName is the name of the inbound rules FortiTatake creates.
const RuleName = "FortiTatake sync"
