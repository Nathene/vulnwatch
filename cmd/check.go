package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// This package will be used to use Grype to check for known vulnerabilities, and then check our current projects against the vulnerabilities

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for vulnerabilities in the go.mod file",
	Run:   check,
}

// This will use Grype to check for known vulnerabilities, and then check our current projects against the vulnerabilities

func check(cmd *cobra.Command, args []string) {
	fmt.Println("Checking for vulnerabilities in the go.mod file")
}
