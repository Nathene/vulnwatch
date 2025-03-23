package cmd

import (
	"fmt"

	"github.com/Nathene/vulnwatch/cmd/config"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of vulnwatch",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(config.Use().Version)
	},
}
