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

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "kestoeso apply --all-secrets --all-namespaces",
	Long: `kestoeso apply allows users to quickly remove secret ownership from KES.
	This allows ESO to fetch ownership and enables a clean migration (i.e. no secrets being deleted).
	A valid kubeconfig is needed for the command to work. Currently, only default setup works.
	Examples:
	kestoeso apply --all-secrets --all-namespaces
	kestoeso apply -s mysecret,mysecret2 --namespace mynamespace
	kestoeso apply --all-secrets --target-owner another-kubernetes-client.io/v1`,
	Run: func(cmd *cobra.Command, args []string) {
		opt := apply.NewApplyOptions()
		opt.AllNamespaces, _ = cmd.Flags().GetBool("all-namespaces")
		opt.AllSecrets, _ = cmd.Flags().GetBool("all-secrets")
		opt.Namespace, _ = cmd.Flags().GetString("namespace")
		opt.TargetOwner, _ = cmd.Flags().GetString("target-owner")
		targetSecrets, _ := cmd.Flags().GetStringSlice("secrets")
		kubeconfig := ""
		if os.Getenv("KUBECONFIG") == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		} else {
			kubeconfig = os.Getenv("KUBECONFIG")
		}
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatal(err)
		}
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

}
