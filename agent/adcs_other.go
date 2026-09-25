//go:build !windows

package main

import "fmt"

// DiscoverADCS is Windows-only (AD CS + certutil). On other platforms it returns
// an error so the CLI can report that AD CS discovery must run on a domain-joined
// Windows host.
func DiscoverADCS() ([]ADCSAsset, string, error) {
	return nil, "", fmt.Errorf("AD CS discovery is only supported on Windows (run this agent on a domain-joined Windows host with certutil)")
}
