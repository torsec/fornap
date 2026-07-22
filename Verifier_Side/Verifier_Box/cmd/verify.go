package cmd

import (
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:     "verify",
	Aliases: []string{"ver"},
	Short:   "Verifier module for Remote Attestation",
	Long:    "Verifies an attestation object sent by an Attester.",
	//Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := Verifier(verbose)
		if err != nil {
			return err
		}
		
		return nil
	},
}

func init() {
	verifyCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print all the steps that are executed")
	rootCmd.AddCommand(verifyCmd)
}
