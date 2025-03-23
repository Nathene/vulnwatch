package database

import "github.com/Nathene/vulnwatch/cmd/common"

type Database interface {
	// We are wanting to know if a vulnerabiltiy is known, but we dont want to download all vulnerabilities, if our projects arent using them. Only store vulnerabilities if they are being used in our projects, and store them in a vulneraboltiies struct, which has the vulnerability name, vulnerabilty severity, and the root directory name of the directory affected.
	StoreVulnerability(vulnerability common.Vulnerability) error
	GetVulnerabilities() ([]common.Vulnerability, error)
}
