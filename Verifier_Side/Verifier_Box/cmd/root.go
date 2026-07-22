package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Verifier is a cli tool for performing Remote Attestation",
	Long: `Verifier is a cli tool for performing Remote Attestation.
It is made up of 2 modules:
	- Register: registers the device willing to perform Remote Attestation and
                performs Credential Activation;
	- Verifier: receives an attestation object and verifies it.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Oops. An error while executing Verifier '%s'\n", err)
		os.Exit(1)
	}
}
