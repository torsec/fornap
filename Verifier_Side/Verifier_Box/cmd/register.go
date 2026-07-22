package cmd

import (
	"github.com/spf13/cobra"
)

var verbose bool
var registerCmd = &cobra.Command{
	Use:     "register",
	Aliases: []string{"reg"},
	Short:   "Register module for Remote Attestation",
	Long:    "Register the device willing to perform Remote Attestation.",
	//Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := Register(verbose)
		if err != nil {
			return err
		}
		
		return nil
	},
}

func init() {
	registerCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print all the steps that are executed")
	rootCmd.AddCommand(registerCmd)
}
