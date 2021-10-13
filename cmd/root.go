package cmd

import (
	"fmt"
	"kestoeso/apis"
	"kestoeso/parser"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kes-to-eso",
	Short: "A tool to convert KES YAML files into ESO YAML files",
	Long: `kes-to-eso is a tool to allow quick conversion between 
kubernetes-external-secrets and external-secrets-operator.
It reads kubernetes-external-secrets deployment declaration and uses
this information alongside with any KES externalSecrets declaration to
provide ESO SecretStores and ExternalSecrets definitions.
Examples:
	kes-to-eso -i path/to/kes/files -o eso/output/dir --to-stdout=false
	kes-to-eso -i path/to/a/single.yaml --kes-namespace=my_custom_namespace
	kes-to-eso -i path/to/kes/files | kubectl apply -f -`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		log.SetOutput(os.Stderr)
		opt := apis.NewOptions()
		opt.ContainerName, _ = cmd.Flags().GetString("kes-container-name")
		opt.DeploymentName, _ = cmd.Flags().GetString("kes-deployment-name")
		opt.Namespace, _ = cmd.Flags().GetString("kes-namespace")
		opt.SecretStore, _ = cmd.Flags().GetBool("secret-store")
		opt.ToStdout, _ = cmd.Flags().GetBool("to-stdout")
		opt.InputPath, _ = cmd.Flags().GetString("input")
		opt.TargetNamespace, _ = cmd.Flags().GetString("target-namespace")
		opt.CopySecretRefs, _ = cmd.Flags().GetBool("copy-secret-refs") // TODO - IMPLEMENT THIS
		_, err := os.Stat(opt.InputPath)
		if err != nil {
			fmt.Println("Missing input path!")
			cmd.Help()
			os.Exit(1)
		}
		opt.OutputPath, _ = cmd.Flags().GetString("output")
		fileinfo, err := os.Stat(opt.OutputPath)
		if !opt.ToStdout {
			if err != nil {
				fmt.Println("Output Path is not a path (to-stdout = false)")
				cmd.Help()
				os.Exit(1)
			} else if fileinfo == nil {
				fmt.Println("Could not find path for output (to-stdout = false)")
				cmd.Help()
				os.Exit(1)
			} else if !fileinfo.IsDir() {
				fmt.Println("output path is not a directory (to-stdout = false)")
				cmd.Help()
				os.Exit(1)
			}

		}
		if opt.SecretStore && !opt.CopySecretRefs {
			log.Warnf("Warning! Backend Secret References are not being copied to the secret store namespaces! This could lead to unintended behavior (--secret-store=true --copy-secret-refs=false)")
		}
		parser.Root(opt)
		os.Exit(0)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().Bool("to-stdout", false, "print generated yamls to STDOUT")
	rootCmd.PersistentFlags().Bool("secret-store", false, "create SecretStores instead of ClusterSecretStores")
	rootCmd.PersistentFlags().Bool("copy-auths-to-namespace", false, "Copy any auth refs that might be necessary for SecretStores to be up and running")
	rootCmd.PersistentFlags().StringP("input", "i", "", "path to lookup for KES yamls")
	rootCmd.PersistentFlags().StringP("output", "o", "", "path ot save ESO-generated yamls")
	rootCmd.PersistentFlags().String("kes-deployment-name", "kubernetes-external-secrets", "name of KES deployment object")
	rootCmd.PersistentFlags().String("kes-container-name", "kubernetes-external-secrets", "name of KES container object")
	rootCmd.PersistentFlags().String("kes-namespace", "default", "namespace where KES is installed")
	rootCmd.PersistentFlags().String("target-namespace", "", "namespace to install files (override KES definitions)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
}
