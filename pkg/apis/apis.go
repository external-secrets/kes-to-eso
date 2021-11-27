package apis

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KESExternalSecretData struct {
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
type KESExternalSecretSpec struct {
	BackendType     string
	VaultMountPoint string
	VaultRole       string
	KvVersion       int
	KeyVaultName    string
	ProjectID       string
	RoleArn         string
	Region          string
	DataFrom        []string
	Data            []KESExternalSecretData
	Template        map[string]interface{}
}
type KESExternalSecret struct {
	Kind       string            `json:"kind,omitempty"`
	ApiVersion string            `json:"apiVersion,omitempty"`
	ObjectMeta metav1.ObjectMeta `json:"metadata"`
	Spec       KESExternalSecretSpec
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
