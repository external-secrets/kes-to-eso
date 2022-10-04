package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	kubeconfig string
	rootCmd    = &cobra.Command{
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
)

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "",
		"kubeconfig path, defaults to $KUBECONFIG or $HOME/.kube/config")

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	kenv := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		if kenv != "" {
			kubeconfig = kenv
		} else {
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
}
