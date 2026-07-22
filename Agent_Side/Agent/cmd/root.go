package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "agent",
	Short: "Agent is a cli tool for performing Remote Attestation",
	Long: `Agent is a cli tool for performing Remote Attestation.
It is made up of 2 modules:
	- Register: creates the endorsement key hierarchy, the storage root hierarchy
	            end the authentication key, then performs the Credential Activation
		    with the Register module of the verifier;
	- Attester: generates an Attestation object and sends it to the Verifier.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Oops. An error while executing Agent '%s'\n", err)
		os.Exit(1)
	}
}
