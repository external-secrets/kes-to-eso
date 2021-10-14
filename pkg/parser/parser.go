package parser

import (
	"fmt"
	"kestoeso/pkg/apis"
	"kestoeso/pkg/provider"
	"kestoeso/pkg/utils"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
		if S.Kind == "SecretStore" &&
			secretStore.Namespace == S.Namespace &&
			secretStore.APIVersion == S.APIVersion &&
			secretStore.Kind == S.Kind &&
			reflect.DeepEqual(secretStore.Spec, S.Spec) {
			return true, idx
		} else if S.Kind == "ClusterSecretStore" &&
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

func readKESFromFile(file string) (apis.KESExternalSecret, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return apis.KESExternalSecret{}, err
	}
	T := apis.KESExternalSecret{}
	err = yaml.Unmarshal(dat, &T)
	if err != nil {
		return apis.KESExternalSecret{}, err
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

func bindProvider(S api.SecretStore, K apis.KESExternalSecret, opt *apis.KesToEsoOptions) (api.SecretStore, bool) {
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
		prov := api.SecretStoreProvider{}
		prov.AWS = &p
		S.Spec.Provider = &prov
		S, err = provider.InstallAWSSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install AWS Backend Specific configuration: %v. Make sure you have set up Controller Pod Identity or manually edit SecretStore before applying it", err)
		}
	case "systemManager":
		p := api.AWSProvider{}
		p.Service = api.AWSServiceParameterStore
		prov := api.SecretStoreProvider{}
		prov.AWS = &p
		p.Role = K.Spec.RoleArn
		p.Region = K.Spec.Region
		S.Spec.Provider = &prov
		S, err = provider.InstallAWSSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install AWS Backend Specific configuration: %v. Make sure you have set up Controller Pod Identity Manually Edit SecretStore before applying it", err)
		}
	case "azureKeyVault": // TODO RECHECK MAPPING ON REAL USE CASE. WHAT KEYVAULTNAME IS USED FOR?
		p := api.AzureKVProvider{}
		prov := api.SecretStoreProvider{}
		prov.AzureKV = &p
		S.Spec.Provider = &prov
		S, err = provider.InstallAzureKVSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install Azure Backend Specific configuration: %v. Manually Edit SecretStore before applying it", err)
		}
	case "gcpSecretsManager":
		p := api.GCPSMProvider{}
		p.ProjectID = K.Spec.ProjectID
		prov := api.SecretStoreProvider{}
		prov.GCPSM = &p
		S.Spec.Provider = &prov
		S, err = provider.InstallGCPSMSecrets(S, opt)
		if err != nil {
			log.Warnf("Failed to Install GCP Backend Specific configuration: %v. Makesure you have set up workload identity or manually edit SecretStore before applying it", err)
		}
	case "ibmcloudSecretsManager":
		prov := api.SecretStoreProvider{}
		prov.IBM = &api.IBMProvider{}
		S.Spec.Provider = &prov
		S, err = provider.InstallIBMSecrets(S, opt)
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
		prov := api.SecretStoreProvider{}
		prov.Vault = &p
		S.Spec.Provider = &prov
		S, err = provider.InstallVaultSecrets(S, opt)
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

func parseGenerals(K apis.KESExternalSecret, E api.ExternalSecret, opt *apis.KesToEsoOptions) (api.ExternalSecret, error) {
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

func Root(opt *apis.KesToEsoOptions) {
	var files []string
	err := filepath.Walk(opt.InputPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		log.Debugln("Looking for ", file)
		K, err := readKESFromFile(file)
		if err != nil {
			panic(err)
		}
		if !utils.IsKES(K) {
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
			err = utils.WriteYaml(S, store_filename, opt.ToStdout)
			if err != nil {
				panic(err)
			}
		}
		E = linkSecretStore(E, S)
		err = utils.WriteYaml(E, secret_filename, opt.ToStdout)
		if err != nil {
			panic(err)
		}
	}
}

// Functions for kubernetes application management
