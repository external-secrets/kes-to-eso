package apis

import (
	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//	"k8s.io/client-go/util/homedir"
	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	//	"k8s.io/client-go/tools/clientcmd"
)

type KESExternalSecret struct {
	Kind       string            `json:"kind,omitempty"`
	ApiVersion string            `json:"apiVersion,omitempty"`
	ObjectMeta metav1.ObjectMeta `json:"metadata"`
	Spec       struct {
		BackendType     string
		VaultMountPoint string
		VaultRole       string
		KvVersion       int
		KeyVaultName    string
		ProjectID       string
		RoleArn         string
		Region          string
		DataFrom        []string
		Data            []struct {
			Key          string
			Name         string
			SecretType   string `json:"secretType"`
			Property     string
			Recursive    string
			Path         string
			VersionStage string
			Version      string
			IsBinary     bool `json:"isBinary"`
		}
		Template api.ExternalSecretTemplate
	}
}

type KesToEsoOptions struct {
	Namespace       string
	DeploymentName  string
	ContainerName   string
	InputPath       string
	OutputPath      string
	ToStdout        bool
	SecretStore     bool
	TargetNamespace string
	CopySecretRefs  bool
}

func NewOptions() *KesToEsoOptions {
	t := KesToEsoOptions{
		Namespace:       "default",
		DeploymentName:  "kubernetes-external-secrets",
		ContainerName:   "kubernetes-external-secrets",
		InputPath:       "",
		OutputPath:      "",
		ToStdout:        false,
		SecretStore:     false,
		TargetNamespace: "",
		CopySecretRefs:  false,
	}
	return &t
}
