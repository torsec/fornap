package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

var printKeys bool
var verbose bool
var registerCmd = &cobra.Command{
	Use:     "register",
	Aliases: []string{"reg"},
	Short:   "Register module for Remote Attestation",
	Long:    "Creates the proper hierarchies and perform activate credentials",
	//Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := Register(printKeys, verbose)
		if err != nil {
			return err
		}
		log.Println("Register module run properly")
		return nil
	},
}

func init() {
	registerCmd.Flags().BoolVarP(&printKeys, "print-keys", "p", false, "Print the EK and AK Public Keys")
	registerCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print all the steps that are executed")
	rootCmd.AddCommand(registerCmd)
}
