package parser

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	//	"k8s.io/client-go/tools/clientcmd"
	//	"k8s.io/client-go/util/homedir"
	yaml "sigs.k8s.io/yaml"
)

var ESOSecretStoreList = make([]api.SecretStore, 0)

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

func readKES(file string) (KESExternalSecret, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return KESExternalSecret{}, err
	}
	T := KESExternalSecret{}
	err = yaml.Unmarshal(dat, &T)
	if err != nil {
		return KESExternalSecret{}, err
	}
	return T, nil
}

//TODO: Allow future versions here
func newESOSecret() api.ExternalSecret {
	d := api.ExternalSecret{}
	d.TypeMeta = metav1.TypeMeta{
		Kind:       "ExternalSecret",
		APIVersion: "external-secrets.io/v1alpha1",
	}
	return d
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func newSecretStore() api.SecretStore {
	d := api.SecretStore{}
	d.TypeMeta = metav1.TypeMeta{
		Kind:       "SecretStore",
		APIVersion: "external-secrets.io/v1alpha1",
	}
	return d
}
func bindProvider(S api.SecretStore, K KESExternalSecret) api.SecretStore {
	backend := K.Spec.BackendType
	switch backend {
	case "secretsManager":
		p := api.AWSProvider{}
		p.Service = api.AWSServiceSecretsManager
		p.Role = K.Spec.RoleArn
		p.Region = K.Spec.Region
		provider := api.SecretStoreProvider{}
		provider.AWS = &p
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "aws-secretstore-autogen-" + randSeq(8)
		S, _ = InstallAWSSecrets(S)
	case "systemManager":
		p := api.AWSProvider{}
		p.Service = api.AWSServiceParameterStore
		provider := api.SecretStoreProvider{}
		provider.AWS = &p
		p.Role = K.Spec.RoleArn
		p.Region = K.Spec.Region
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "aws-secretstore-autogen-" + randSeq(8)
		S, _ = InstallAWSSecrets(S)
	case "azureKeyVault": // TODO RECHECK MAPPING ON REAL USE CASE. WHAT KEYVAULTNAME IS USED FOR?
		p := api.AzureKVProvider{}
		provider := api.SecretStoreProvider{}
		provider.AzureKV = &p
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "azurekv-secretstore-autogen-" + randSeq(8)
		S, _ = InstallAzureKVSecrets(S)
	case "gcpSecretsManager":
		p := api.GCPSMProvider{}
		p.ProjectID = K.Spec.ProjectID
		provider := api.SecretStoreProvider{}
		provider.GCPSM = &p
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "gcp-secretstore-autogen-" + randSeq(8)
		S, _ = InstallGCPSMSecrets(S)
	case "ibmcloudSecretsManager":
		provider := api.SecretStoreProvider{}
		provider.IBM = &api.IBMProvider{}
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "ibm-secretstore-autogen-" + randSeq(8)
		S, _ = InstallIBMSecrets(S)
	case "vault": // TODO RECHECK MAPPING ON REAL USE CASE
		p := api.VaultProvider{}
		if K.Spec.KvVersion == 1 {
			p.Version = api.VaultKVStoreV1
		} else {
			p.Version = api.VaultKVStoreV2
		}
		provider := api.SecretStoreProvider{}
		provider.Vault = &p
		S.Spec.Provider = &provider
		S.ObjectMeta.Name = "vault-secretstore-autogen-" + randSeq(8)
		S, _ = InstallVaultSecrets(S)
		fmt.Println(S)
		if K.Spec.VaultMountPoint != "" {
			S.Spec.Provider.Vault.Auth.Kubernetes.Path = K.Spec.VaultMountPoint
		}
		if K.Spec.VaultRole != "" {
			S.Spec.Provider.Vault.Auth.Kubernetes.Role = K.Spec.VaultRole
		}
		fmt.Println(S)
	case "alicloud": // TODO DEVELOP
	case "akeyless": // TODO DEVELOP
	default:
	}
	return S
}

func parseGenerals(K KESExternalSecret, E api.ExternalSecret) (api.ExternalSecret, error) {
	secret := E
	secret.ObjectMeta.Name = K.ObjectMeta.Name
	secret.Spec.Target.Name = K.ObjectMeta.Name // Inherits default in KES, so we should do the same approach here
	var refKey string
	for _, kesSecretData := range K.Spec.Data {
		if kesSecretData.SecretType != "" {
			refKey = kesSecretData.SecretType + "/" + kesSecretData.Key
		} else {
			refKey = kesSecretData.Key
		}
		esoRemoteRef := api.ExternalSecretDataRemoteRef{
			Key:      refKey,
			Property: kesSecretData.Property,
			Version:  kesSecretData.Version}
		esoSecretData := api.ExternalSecretData{
			SecretKey: kesSecretData.Name,
			RemoteRef: esoRemoteRef}
		secret.Spec.Data = append(secret.Spec.Data, esoSecretData)
	}
	for _, kesSecretDataFrom := range K.Spec.DataFrom {
		esoDataFrom := api.ExternalSecretDataRemoteRef{
			Key: kesSecretDataFrom,
		}
		secret.Spec.DataFrom = append(secret.Spec.DataFrom, esoDataFrom)
	}
	secret.Spec.Target.Template = &K.Spec.Template
	return secret, nil

}

func linkSecretStore(E api.ExternalSecret, S api.SecretStore) api.ExternalSecret {
	ext := E
	ext.Spec.SecretStoreRef.Name = S.ObjectMeta.Name
	ext.Spec.SecretStoreRef.Kind = "SecretStore"
	return ext
}

func isKES(K KESExternalSecret) bool {
	return K.Kind == "ExternalSecret"
}

func newYaml() {
	fmt.Println("----------")
}

// all below are helper function for initial development. They are going to be removed afterwards

// Helper function for initial developments
func do_the_thing(path string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	K, err := readKES(path)
	if err != nil {
		return err
	}
	if !isKES(K) {
		return nil
	}
	E, err := parseGenerals(K, newESOSecret())
	if err != nil {
		return err
	}
	S := newSecretStore()
	S = bindProvider(S, K)
	dat, err := yaml.Marshal(S)
	if err != nil {
		return err
	}
	fmt.Println(string(dat))
	newYaml()
	E = linkSecretStore(E, S)
	dat, err = yaml.Marshal(E)
	if err != nil {
		return err
	}
	fmt.Println(string(dat))
	newYaml()
	if err != nil {
		return err
	}
	return nil
}

// Helper function for initial developments
func ParseKes(path string) {
	err := filepath.Walk(path, do_the_thing)
	if err != nil {
		log.Fatalf("Something went wrong!\n%v\n", err)
		return
	}
}

// Functions for kubernetes application management

func initConfig() (*kubernetes.Clientset, error) {
	kubeconfig := "/home/gustavo/.kube/config"

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

type KesDeploymentTarget struct {
	Namespace           string
	DeploymentName      string
	ContainerName       string
	GCPSecretVolumeName string
	GCPSecretKey        string
}

func NewDeploymentTarget() *KesDeploymentTarget {
	t := KesDeploymentTarget{
		Namespace:           "default",
		DeploymentName:      "kubernetes-external-secrets",
		ContainerName:       "kubernetes-external-secrets",
		GCPSecretVolumeName: "gcp-creds",
		GCPSecretKey:        "gcp-creds.json",
	}
	return &t
}

func getSecretValue(name string, key string, namespace string) (string, error) {
	clientset, err := initConfig()
	if err != nil {
		return "", err
	}
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	fmt.Printf("Context: %v/secrets/%v/%v\n", namespace, name, key)
	value := secret.Data[key]
	return string(value), nil
}

func updateOrCreateSecret(secret *corev1.Secret, essecret *esmeta.SecretKeySelector, secretValue string) (*corev1.Secret, error) {
	secret.Name = essecret.Name
	secret.Namespace = *essecret.Namespace
	secret.Type = corev1.SecretTypeOpaque
	secret.TypeMeta.Kind = "Secret"
	secret.TypeMeta.APIVersion = "v1"
	if len(secret.StringData) > 0 {
		secret.StringData[essecret.Key] = secretValue
	} else {
		temp := map[string]string{
			essecret.Key: secretValue,
		}
		secret.StringData = temp
	}
	return secret, nil
}

// Provider functions to install Context on a given secret store.

func InstallAWSSecrets(S api.SecretStore) (api.SecretStore, error) {
	ans := S
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := NewDeploymentTarget() // TODO - configure Deployment Target out of here, and use it like a big target configurable by CLI.
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	containers := deployment.Spec.Template.Spec.Containers
	var accessKeyIdSecretKeyRefKey, accessKeyIdSecretKeyRefName string
	var secretAccessKeySecretKeyRefKey, secretAccessKeySecretKeyRefName string
	var newsecret = &corev1.Secret{}
	for _, container := range containers {
		if container.Name == target.ContainerName {
			containerEnvs := container.Env
			for _, env := range containerEnvs {
				if env.Name == "AWS_ACCESS_KEY_ID" {
					if env.ValueFrom != nil {
						accessKeyIdSecretKeyRefName = env.ValueFrom.SecretKeyRef.Name
						accessKeyIdSecretKeyRefKey = env.ValueFrom.SecretKeyRef.Key
					} else if env.Value != "" {
						accessKeyIdSecretKeyRefName = "aws-secrets"
						accessKeyIdSecretKeyRefKey = "access-key-id"
						keySelector := esmeta.SecretKeySelector{
							Name:      accessKeyIdSecretKeyRefName,
							Namespace: &target.Namespace,
							Key:       accessKeyIdSecretKeyRefKey,
						}
						newsecret, err = updateOrCreateSecret(newsecret, &keySelector, env.Value)
						if err != nil {
							panic(err)
						}
					}
				}
				if env.Name == "AWS_SECRET_ACCESS_KEY" {
					if env.ValueFrom != nil {
						secretAccessKeySecretKeyRefName = env.ValueFrom.SecretKeyRef.Name
						secretAccessKeySecretKeyRefKey = env.ValueFrom.SecretKeyRef.Key
					} else if env.Value != "" {
						secretAccessKeySecretKeyRefName = "aws-secrets"
						secretAccessKeySecretKeyRefKey = "secret-access-key"
						secretSelector := esmeta.SecretKeySelector{
							Name:      secretAccessKeySecretKeyRefName,
							Namespace: &target.Namespace,
							Key:       secretAccessKeySecretKeyRefKey,
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							panic(err)
						}
					}
				}
				if accessKeyIdSecretKeyRefName != "" && secretAccessKeySecretKeyRefName != "" {
					break
				}
			}
			break
		}
	}
	awsSecretRef := api.AWSAuthSecretRef{
		AccessKeyID: esmeta.SecretKeySelector{
			Name:      accessKeyIdSecretKeyRefName,
			Key:       accessKeyIdSecretKeyRefKey,
			Namespace: &target.Namespace,
		},
		SecretAccessKey: esmeta.SecretKeySelector{
			Name:      secretAccessKeySecretKeyRefName,
			Key:       secretAccessKeySecretKeyRefKey,
			Namespace: &target.Namespace,
		},
	}
	ans.Spec.Provider.AWS.Auth.SecretRef = &awsSecretRef
	if newsecret != nil {
		dat, err := yaml.Marshal(newsecret)
		if err != nil {
			return S, err
		}
		fmt.Println(string(dat))
		newYaml()
	}
	return ans, nil
}

func InstallVaultSecrets(S api.SecretStore) (api.SecretStore, error) {
	ans := S
	authRef := api.VaultKubernetesAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := NewDeploymentTarget() // TODO - configure Deployment Target out of here, and use it like a big target configurable by CLI.
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	newsecret := &corev1.Secret{}
	containers := deployment.Spec.Template.Spec.Containers
	for _, container := range containers {
		if container.Name == target.ContainerName {
			envs := container.Env
			for _, env := range envs {
				if env.Name == "VAULT_ADDR" {
					if env.Value != "" {
						ans.Spec.Provider.Vault.Server = env.Value
					} else if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						value, err := getSecretValue(name, key, target.Namespace)
						if err != nil {
							panic("Could not find secret value for VAULT_ADDR")
						}
						ans.Spec.Provider.Vault.Server = value
					}
				}
				if env.Name == "DEFAULT_VAULT_MOUNT_POINT" {
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						value, err := getSecretValue(name, key, target.Namespace)
						if err != nil {
							panic("Could not find secret value for DEFAULT_VAULT_MOUNT_POINT")
						}
						authRef.Path = value
					} else if env.Value != "" {
						authRef.Path = env.Value
					}
				}
				if env.Name == "DEFAULT_VAULT_ROLE" {
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						value, err := getSecretValue(name, key, target.Namespace)
						if err != nil {
							panic("Could not find secret value for DEFAULT_VAULT_MOUNT_ROLE")
						}
						authRef.Role = value
					} else if env.Value != "" {
						authRef.Role = env.Value
					}
				}
			}
		}
	}
	ans.Spec.Provider.Vault.Auth.Kubernetes = &authRef
	if newsecret != nil {
		dat, err := yaml.Marshal(newsecret)
		if err != nil {
			return S, err
		}
		fmt.Println(string(dat))
		newYaml()
	}
	return ans, nil
}

func InstallGCPSMSecrets(S api.SecretStore) (api.SecretStore, error) {
	ans := S
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := NewDeploymentTarget() // TODO - configure Deployment Target out of here, and use it like a big target configurable by CLI.
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	volumes := deployment.Spec.Template.Spec.Volumes
	for _, volume := range volumes {
		if volume.Name == target.GCPSecretVolumeName {
			secretName := volume.Secret.SecretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Name = secretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Key = target.GCPSecretKey
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Namespace = &target.Namespace
		}
	}
	return ans, nil
}

func InstallAzureKVSecrets(S api.SecretStore) (api.SecretStore, error) {
	ans := S
	authRef := api.AzureKVAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := NewDeploymentTarget() // TODO - configure Deployment Target out of here, and use it like a big target configurable by CLI.
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	newsecret := &corev1.Secret{}
	containers := deployment.Spec.Template.Spec.Containers
	for _, container := range containers {
		if container.Name == target.ContainerName {
			envs := container.Env
			for _, env := range envs {
				if env.Name == "AZURE_TENANT_ID" {
					if env.Value != "" {
						svc := env.Value
						ans.Spec.Provider.AzureKV.TenantID = &svc
					} else if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						value, err := getSecretValue(name, key, target.Namespace)
						if err != nil {
							panic("Could not find secret value for AZURE_TENANT_ID")
						}
						ans.Spec.Provider.AzureKV.TenantID = &value
					}
				}
				if env.Name == "AZURE_CLIENT_ID" {
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						clientSelector := esmeta.SecretKeySelector{
							Name:      name,
							Key:       key,
							Namespace: &target.Namespace,
						}
						authRef.ClientID = &clientSelector
					} else if env.Value != "" {
						clientSelector := esmeta.SecretKeySelector{
							Name:      "azure-secrets",
							Namespace: &target.Namespace,
							Key:       "client-id",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &clientSelector, env.Value)
						if err != nil {
							panic(err)
						}
						authRef.ClientID = &clientSelector
					}
				}
				if env.Name == "AZURE_CLIENT_SECRET" {
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						secretSelector := esmeta.SecretKeySelector{
							Name:      name,
							Key:       key,
							Namespace: &target.Namespace,
						}
						authRef.ClientSecret = &secretSelector
					} else if env.Value != "" {
						secretSelector := esmeta.SecretKeySelector{
							Name:      "azure-secrets",
							Namespace: &target.Namespace,
							Key:       "client-secrets",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							panic(err)
						}
						authRef.ClientSecret = &secretSelector
					}

				}
			}
		}
	}
	ans.Spec.Provider.AzureKV.AuthSecretRef = &authRef
	if newsecret != nil {
		dat, err := yaml.Marshal(newsecret)
		if err != nil {
			return S, err
		}
		fmt.Println(string(dat))
		newYaml()
	}
	return ans, nil
}

func InstallIBMSecrets(S api.SecretStore) (api.SecretStore, error) {
	ans := S
	authRef := api.IBMAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := NewDeploymentTarget() // TODO - configure Deployment Target out of here, and use it like a big target configurable by CLI.
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	newsecret := &corev1.Secret{}
	containers := deployment.Spec.Template.Spec.Containers
	for _, container := range containers {
		if container.Name == target.ContainerName {
			envs := container.Env
			for _, env := range envs {
				if env.Name == "IBM_CLOUD_SECRETS_MANAGER_API_APIKEY" {
					if env.Value != "" {
						secretSelector := esmeta.SecretKeySelector{
							Name:      "ibm-secrets",
							Namespace: &target.Namespace,
							Key:       "api-key",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							panic(err)
						}
						authRef.SecretRef.SecretAPIKey = secretSelector
					} else if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						secretSelector := esmeta.SecretKeySelector{
							Name:      name,
							Key:       key,
							Namespace: &target.Namespace,
						}
						authRef.SecretRef.SecretAPIKey = secretSelector
					}
				}
				if env.Name == "IBM_CLOUD_SECRETS_MANAGER_API_ENDPOINT" {
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						value, err := getSecretValue(name, key, target.Namespace)
						if err != nil {
							panic("Could not find secret value for IBM_CLOUD_SECRETS_MANAGER_ENDPOINT")
						}
						ans.Spec.Provider.IBM.ServiceURL = &value
					} else if env.Value != "" {
						svc := env.Value
						ans.Spec.Provider.IBM.ServiceURL = &svc
					}
				}
				//if env.Name == "IBM_CLOUD_SECRETS_MANAGER_API_AUTH_TYPE" {
				// TODO - FIGURE OUT WHY WE NEED THIS
				//}
			}
		}
	}
	ans.Spec.Provider.IBM.Auth = authRef
	if newsecret != nil {
		dat, err := yaml.Marshal(newsecret)
		if err != nil {
			return S, err
		}
		fmt.Println(string(dat))
		newYaml()
	}
	return ans, nil

}
