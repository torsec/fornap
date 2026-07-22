package cmd

import (
	"fmt"
	"log"
	"time"

	c "config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var attestCmd = &cobra.Command{
	Use:     "attester",
	Aliases: []string{"att"},
	Short:   "Attester module for Remote Attestation",
	Long:    "Creates the attestation object and sends it to a Verifier.",
	//Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		configuration := ReadConf()
		seconds := configuration.AttestationPeriod.Seconds
		duration := time.Duration(seconds) * time.Second
		err := Attest(verbose)
		if err != nil {
			//log.Println(err)
			return err
		}
		if !configuration.WaitVerifier.Wait {
			log.Println("Attester module run properly")
			for range time.Tick(duration) {
				err := Attest(verbose)
				if err != nil {
					log.Println(err)
					return err
				}
				log.Println("Attester module run properly")
			}
		}
		return nil
	},
}

func init() {
	attestCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print all the steps that are executed")
	rootCmd.AddCommand(attestCmd)
}

func ReadConf() c.Configurations {
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath("./config")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yml")
	var configuration c.Configurations

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}
	return configuration
}
