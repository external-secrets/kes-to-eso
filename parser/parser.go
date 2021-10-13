package parser

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	//	"k8s.io/client-go/util/homedir"
	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	//	"k8s.io/client-go/tools/clientcmd"
	yaml "sigs.k8s.io/yaml"
)

// Store DB Functions

type SecretStoreDB []api.SecretStore
type StoreDB interface {
	Exists(S api.SecretStore) (bool, int)
}

func (storedb SecretStoreDB) Exists(S api.SecretStore) (bool, int) {
	for idx, secretStore := range storedb {
		if secretStore.Namespace == S.Namespace &&
			secretStore.APIVersion == S.APIVersion &&
			secretStore.Kind == S.Kind &&
			reflect.DeepEqual(secretStore.Spec, S.Spec) {
			return true, idx
		}
	}
	return false, -1
}

var ESOSecretStoreList = make(SecretStoreDB, 0)

//

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

func NewDeploymentTarget() *KesToEsoOptions {
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

func readKESFromFile(file string) (KESExternalSecret, error) {
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

var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func newSecretStore(secretStore bool) api.SecretStore {
	d := api.SecretStore{}
	d.TypeMeta = metav1.TypeMeta{
		APIVersion: "external-secrets.io/v1alpha1",
	}
	if secretStore {
		d.TypeMeta.Kind = "SecretStore"
	} else {
		d.TypeMeta.Kind = "ClusterSecretStore"
	}
	return d
}
func bindProvider(S api.SecretStore, K KESExternalSecret, opt *KesToEsoOptions) (api.SecretStore, bool) {
	if opt.TargetNamespace != "" {
		S.ObjectMeta.Namespace = opt.TargetNamespace
	} else {
		S.ObjectMeta.Namespace = K.ObjectMeta.Namespace
	}
	var err error
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
		S, err = InstallAWSSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install AWS Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
	case "systemManager":
		p := api.AWSProvider{}
		p.Service = api.AWSServiceParameterStore
		provider := api.SecretStoreProvider{}
		provider.AWS = &p
		p.Role = K.Spec.RoleArn
		p.Region = K.Spec.Region
		S.Spec.Provider = &provider
		S, err = InstallAWSSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install AWS Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
	case "azureKeyVault": // TODO RECHECK MAPPING ON REAL USE CASE. WHAT KEYVAULTNAME IS USED FOR?
		p := api.AzureKVProvider{}
		provider := api.SecretStoreProvider{}
		provider.AzureKV = &p
		S.Spec.Provider = &provider
		S, err = InstallAzureKVSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install Azure Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
	case "gcpSecretsManager":
		p := api.GCPSMProvider{}
		p.ProjectID = K.Spec.ProjectID
		provider := api.SecretStoreProvider{}
		provider.GCPSM = &p
		S.Spec.Provider = &provider
		S, err = InstallGCPSMSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install GCP Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
	case "ibmcloudSecretsManager":
		provider := api.SecretStoreProvider{}
		provider.IBM = &api.IBMProvider{}
		S.Spec.Provider = &provider
		S, err = InstallIBMSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install IBM Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
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
		S, err = InstallVaultSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install Vault Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
		if K.Spec.VaultMountPoint != "" {
			S.Spec.Provider.Vault.Auth.Kubernetes.Path = K.Spec.VaultMountPoint
		}
		if K.Spec.VaultRole != "" {
			S.Spec.Provider.Vault.Auth.Kubernetes.Role = K.Spec.VaultRole
		}
	case "alicloud":
	case "akeyless":
	default:
	}
	exists, pos := ESOSecretStoreList.Exists(S)
	if !exists {
		S.ObjectMeta.Name = fmt.Sprintf("%v-secretstore-autogen-%v", strings.ToLower(backend), randSeq(8))
		ESOSecretStoreList = append(ESOSecretStoreList, S)
		return S, true
	} else {
		return ESOSecretStoreList[pos], false
	}
}
func writeYaml(S interface{}, filepath string, to_stdout bool) error {
	dat, err := yaml.Marshal(S)
	if err != nil {
		return err
	}
	if to_stdout {
		fmt.Println(string(dat))
		newYaml()
	} else {
		err = os.WriteFile(filepath, dat, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseGenerals(K KESExternalSecret, E api.ExternalSecret, opt *KesToEsoOptions) (api.ExternalSecret, error) {
	secret := E
	secret.ObjectMeta.Name = K.ObjectMeta.Name
	secret.Spec.Target.Name = K.ObjectMeta.Name // Inherits default in KES, so we should do the same approach here
	if opt.TargetNamespace != "" {
		secret.ObjectMeta.Namespace = opt.TargetNamespace
	} else {
		secret.ObjectMeta.Namespace = K.ObjectMeta.Namespace
	}
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
	ext.Spec.SecretStoreRef.Kind = S.TypeMeta.Kind
	return ext
}

func isKES(K KESExternalSecret) bool {
	return K.Kind == "ExternalSecret" && K.ApiVersion == "kubernetes-client.io/v1"
}

func newYaml() {
	fmt.Println("---")
}

func ParseKes(opt *KesToEsoOptions) {
	var files []string
	filepath.Walk(opt.InputPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	for _, file := range files {
		log.Debugln("Looking for ", file)
		K, err := readKESFromFile(file)
		if err != nil {
			panic(err)
		}
		if !isKES(K) {
			log.Warnf("Not a KES File: %v\n", file)
			continue
		}
		E, err := parseGenerals(K, newESOSecret(), opt)
		if err != nil {
			panic(err)
		}
		S := newSecretStore(opt.SecretStore)
		S, newProvider := bindProvider(S, K, opt)
		secret_filename := fmt.Sprintf("%v/external-secret-%v.yaml", opt.OutputPath, E.ObjectMeta.Name)
		if newProvider {
			store_filename := fmt.Sprintf("%v/secret-store-%v.yaml", opt.OutputPath, S.ObjectMeta.Name)
			err = writeYaml(S, store_filename, opt.ToStdout)
			if err != nil {
				panic(err)
			}
		}
		E = linkSecretStore(E, S)
		err = writeYaml(E, secret_filename, opt.ToStdout)
		if err != nil {
			panic(err)
		}
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

func getSecretValue(name string, key string, namespace string) (string, error) {
	clientset, err := initConfig()
	if err != nil {
		return "", err
	}
	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
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

func InstallAWSSecrets(S api.SecretStore, opt *KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := *opt
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
						ns := S.ObjectMeta.Namespace
						if opt.TargetNamespace != "" {
							ns = opt.TargetNamespace
						}
						keySelector := esmeta.SecretKeySelector{
							Name:      accessKeyIdSecretKeyRefName,
							Namespace: &ns,
							Key:       accessKeyIdSecretKeyRefKey,
						}
						newsecret, err = updateOrCreateSecret(newsecret, &keySelector, env.Value)
						if err != nil {
							return S, err
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
						ns := S.ObjectMeta.Namespace
						if opt.TargetNamespace != "" {
							ns = opt.TargetNamespace
						}
						secretSelector := esmeta.SecretKeySelector{
							Name:      secretAccessKeySecretKeyRefName,
							Namespace: &ns,
							Key:       secretAccessKeySecretKeyRefKey,
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							return S, err
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
	if newsecret.ObjectMeta.Name != "" {
		secret_filename := fmt.Sprintf("%v/secret-%v.yaml", target.OutputPath, newsecret.ObjectMeta.Name)
		writeYaml(newsecret, secret_filename, target.ToStdout)
	}
	if awsSecretRef.AccessKeyID.Name == "" || awsSecretRef.SecretAccessKey.Name == "" {
		return S, errors.New("could not find aws credential information on kes deployment")
	}
	return ans, nil
}

func InstallVaultSecrets(S api.SecretStore, opt *KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.VaultKubernetesAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := *opt
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
							return S, errors.New("could not find env value for vault_addr")
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
							return S, errors.New("could not find secret value for default_vault_mount_point")
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
							return S, errors.New("could not find secret value for default_vault_role")
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
	if newsecret.ObjectMeta.Name != "" {
		secret_filename := fmt.Sprintf("%v/secret-%v.yaml", target.OutputPath, newsecret.ObjectMeta.Name)
		writeYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.Role == "" || authRef.Path == "" || ans.Spec.Provider.Vault.Server == "" {
		return ans, errors.New("credentials for vault not found in kes deployment")
	}
	return ans, nil
}

func InstallGCPSMSecrets(S api.SecretStore, opt *KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := *opt
	deployment, err := clientset.AppsV1().Deployments(target.Namespace).Get(context.TODO(), target.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return S, err
	}
	containers := deployment.Spec.Template.Spec.Containers
	volumeName := ""
	keyName := ""
	for _, container := range containers {
		if container.Name == target.ContainerName {
			mountPath := ""
			containerEnvs := container.Env
			for _, env := range containerEnvs {
				if env.Name == "GOOGLE_APPLICATION_CREDENTIALS" {
					mountPathSlice := strings.Split(env.Value, "/")
					for idx, path := range mountPathSlice {
						if idx == 0 {
							mountPath = path
						} else if idx < len(mountPathSlice)-1 {
							mountPath = mountPath + "/" + path
						}
					}
					keyName = mountPathSlice[len(mountPathSlice)-1]
				}
			}
			volumeMounts := container.VolumeMounts
			for _, mount := range volumeMounts {
				if mount.MountPath == mountPath {
					volumeName = mount.Name
				}
			}
		}
	}
	volumes := deployment.Spec.Template.Spec.Volumes
	for _, volume := range volumes {
		if volume.Name == volumeName {
			secretName := volume.Secret.SecretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Name = secretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Key = keyName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Namespace = &target.Namespace
		}
	}
	if reflect.DeepEqual(ans, S) {
		return ans, errors.New("credentials for gcp sm not found in kes deployment")
	}
	return ans, nil
}

func InstallAzureKVSecrets(S api.SecretStore, opt *KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.AzureKVAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := *opt
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
							return S, errors.New("could not find secret value for azure_tenant_id")
						}
						ans.Spec.Provider.AzureKV.TenantID = &value
					}
				}
				if env.Name == "AZURE_CLIENT_ID" {
					ns := S.ObjectMeta.Namespace
					if opt.TargetNamespace != "" {
						ns = opt.TargetNamespace
					}
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						clientSelector := esmeta.SecretKeySelector{
							Name:      name,
							Key:       key,
							Namespace: &ns,
						}
						authRef.ClientID = &clientSelector
					} else if env.Value != "" {
						clientSelector := esmeta.SecretKeySelector{
							Name:      "azure-secrets",
							Namespace: &ns,
							Key:       "client-id",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &clientSelector, env.Value)
						if err != nil {
							return S, err
						}
						authRef.ClientID = &clientSelector
					}
				}
				if env.Name == "AZURE_CLIENT_SECRET" {
					ns := S.ObjectMeta.Namespace
					if opt.TargetNamespace != "" {
						ns = opt.TargetNamespace
					}
					if env.ValueFrom != nil {
						key := env.ValueFrom.SecretKeyRef.Key
						name := env.ValueFrom.SecretKeyRef.Name
						secretSelector := esmeta.SecretKeySelector{
							Name:      name,
							Key:       key,
							Namespace: &ns,
						}
						authRef.ClientSecret = &secretSelector
					} else if env.Value != "" {
						secretSelector := esmeta.SecretKeySelector{
							Name:      "azure-secrets",
							Namespace: &ns,
							Key:       "client-secrets",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							return S, err
						}
						authRef.ClientSecret = &secretSelector
					}

				}
			}
		}
	}
	ans.Spec.Provider.AzureKV.AuthSecretRef = &authRef
	if newsecret.ObjectMeta.Name != "" {
		secret_filename := fmt.Sprintf("%v/secret-%v.yaml", target.OutputPath, newsecret.ObjectMeta.Name)
		writeYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.ClientID == nil || authRef.ClientSecret == nil {
		return ans, errors.New("credentials for azure not found in kes deployment")
	}
	return ans, nil
}

func InstallIBMSecrets(S api.SecretStore, opt *KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.IBMAuth{}
	clientset, err := initConfig()
	if err != nil {
		return S, err
	}
	target := *opt
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
						ns := S.ObjectMeta.Namespace
						if opt.TargetNamespace != "" {
							ns = opt.TargetNamespace
						}
						secretSelector := esmeta.SecretKeySelector{
							Name:      "ibm-secrets",
							Namespace: &ns,
							Key:       "api-key",
						}
						newsecret, err = updateOrCreateSecret(newsecret, &secretSelector, env.Value)
						if err != nil {
							return S, err
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
							return S, errors.New("could not find secret value for ibm_cloud_secrets_manager_api_endpoint")
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
	if newsecret.ObjectMeta.Name != "" {
		secret_filename := fmt.Sprintf("%v/secret-%v.yaml", target.OutputPath, newsecret.ObjectMeta.Name)
		writeYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.SecretRef.SecretAPIKey.Name == "" {
		return ans, errors.New("credentials for ibm cloud not found in kes deployment. edit secretstore definitions before using it")
	}
	return ans, nil

}
