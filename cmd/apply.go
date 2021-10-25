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
	"kestoeso/pkg/apply"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// applyCmd represents the apply command
var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		opt := apply.NewApplyOptions()
		opt.AllNamespaces, _ = cmd.Flags().GetBool("all-namespaces")
		opt.AllSecrets, _ = cmd.Flags().GetBool("all-secrets")
		opt.Namespace, _ = cmd.Flags().GetString("namespace")
		opt.TargetOwner, _ = cmd.Flags().GetString("target-owner")
		targetSecrets, _ := cmd.Flags().GetStringSlice("secrets")
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
		client := apply.ApplyClient{
			Client:  clientset,
			Options: opt,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = apply.Root(ctx, &client, targetSecrets)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)

	},
}

func init() {
	rootCmd.AddCommand(applyCmd)
	var empty = make([]string, 0)
	applyCmd.Flags().BoolP("all-namespaces", "A", false, "Updates secrets for All Namespaces")
	applyCmd.Flags().Bool("all-secrets", false, "updates all secrets from one namespace")
	applyCmd.Flags().StringP("namespace", "n", "default", "Target namespace to look up for secrets")
	applyCmd.Flags().StringSliceP("secrets", "s", empty, "list of secret names to be updated")
	applyCmd.Flags().String("target-owner", "kubernetes-client.io/v1", "Target ownership value that secrets are going to be updated")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// applyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// applyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
