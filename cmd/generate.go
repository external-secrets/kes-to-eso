/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"fmt"
	"kestoeso/pkg/apis"
	"kestoeso/pkg/parser"
	"kestoeso/pkg/provider"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A tool to convert KES YAML files into ESO YAML files",
	Long: `kes-to-eso generate is a tool to allow quick conversion between 
	kubernetes-external-secrets and external-secrets-operator.
	It reads kubernetes-external-secrets deployment declaration and uses
	this information alongside with any KES externalSecrets declaration to
	provide ESO SecretStores and ExternalSecrets definitions.
	Examples:
		kes-to-eso generate -i path/to/kes/files -o eso/output/dir --to-stdout=false
		kes-to-eso generate -i path/to/a/single.yaml --kes-namespace=my_custom_namespace
		kes-to-eso generate -i path/to/kes/files | kubectl apply -f -`,
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
			err := cmd.Help()
			if err != nil {
				os.Exit(1)
			}
			os.Exit(1)
		}
		opt.OutputPath, _ = cmd.Flags().GetString("output")
		fileinfo, err := os.Stat(opt.OutputPath)
		if !opt.ToStdout {
			if err != nil {
				fmt.Println("Output Path is not a path (to-stdout = false)")
				err := cmd.Help()
				if err != nil {
					os.Exit(1)
				}
				os.Exit(1)
			} else if fileinfo == nil {
				fmt.Println("Could not find path for output (to-stdout = false)")
				err := cmd.Help()
				if err != nil {
					os.Exit(1)
				}
				os.Exit(1)
			} else if !fileinfo.IsDir() {
				fmt.Println("output path is not a directory (to-stdout = false)")
				err := cmd.Help()
				if err != nil {
					os.Exit(1)
				}
				os.Exit(1)
			}

		}
		if opt.SecretStore && !opt.CopySecretRefs {
			log.Warnf("Warning! Backend Secret References are not being copied to the secret store namespaces! This could lead to unintended behavior (--secret-store=true --copy-secret-refs=false)")
		}
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatal(err)
		}
		// create the clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		client := provider.KesToEsoClient{
			Client:  clientset,
			Options: opt,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		parser.Root(ctx, &client)
		os.Exit(0)

	},
}

func init() {
	// Here you will define your flags and configuration settings.
	generateCmd.Flags().Bool("to-stdout", false, "print generated yamls to STDOUT")
	//	rootCmd.PersistentFlags().Bool("secret-store", false, "create SecretStores instead of ClusterSecretStores")
	//  rootCmd.PersistentFlags().Bool("copy-auths-to-namespace", false, "Copy any auth refs that might be necessary for SecretStores to be up and running")
	generateCmd.Flags().StringP("input", "i", "", "path to lookup for KES yamls")
	generateCmd.Flags().StringP("output", "o", "", "path ot save ESO-generated yamls")
	generateCmd.Flags().String("kes-deployment-name", "kubernetes-external-secrets", "name of KES deployment object")
	generateCmd.Flags().String("kes-container-name", "kubernetes-external-secrets", "name of KES container object")
	generateCmd.Flags().StringP("kes-namespace", "n", "default", "namespace where KES is installed")
	generateCmd.Flags().String("target-namespace", "", "namespace to install files (not recommended - overrides KES-ExternalSecrets definitions)")

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// generateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// generateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
