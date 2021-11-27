package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "kestoeso",
	Short: "A tool to convert KES YAML files into ESO YAML files",
	Long: `kes-to-eso is a tool to allow quick conversion between 
kubernetes-external-secrets and external-secrets-operator.
It reads kubernetes-external-secrets deployment declaration and uses
this information alongside with any KES externalSecrets declaration to
provide ESO SecretStores and ExternalSecrets definitions.
Examples:
	kes-to-eso generate -i path/to/kes/files | kubectl apply -f -
	kes-to-eso apply --target-namespace=my-ns`,
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.AddCommand(generateCmd)
	cobra.OnInitialize(initConfig)

}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".test")
	}
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

}
