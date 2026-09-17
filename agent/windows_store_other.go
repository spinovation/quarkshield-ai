//go:build !windows && !darwin && !linux

package main

func AuditPlatformSystemStores() ([]AuditResult, []AuditResult) {
	return nil, nil
}

