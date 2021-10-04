package main

import (
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"path/filepath"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	d.ObjectMeta.Name = "SS-auto-gen-" + randSeq(8)
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
	case "systemManager":
		p := api.AWSProvider{}
		p.Service = api.AWSServiceParameterStore
		provider := api.SecretStoreProvider{}
		provider.AWS = &p
		p.Role = K.Spec.RoleArn
		p.Region = K.Spec.Region
		S.Spec.Provider = &provider
	case "azureKeyVault":
		p := api.AzureKVProvider{}
		p.VaultURL = &K.Spec.KeyVaultName
		provider := api.SecretStoreProvider{}
		provider.AzureKV = &p
		S.Spec.Provider = &provider
	case "gcpSecretsManager":
		p := api.GCPSMProvider{}
		p.ProjectID = K.Spec.ProjectID
		provider := api.SecretStoreProvider{}
		provider.GCPSM = &p
		S.Spec.Provider = &provider
	case "ibmcloudSecretsManager":

		provider := api.SecretStoreProvider{}
		provider.IBM = &api.IBMProvider{}
		S.Spec.Provider = &provider
	case "vault": // TODO - Where does vaultRole goes?
		p := api.VaultProvider{}
		if K.Spec.KvVersion == 1 {
			p.Version = api.VaultKVStoreV1
		} else {
			p.Version = api.VaultKVStoreV2
		}
		p.Path = K.Spec.VaultMountPoint
		provider := api.SecretStoreProvider{}
		provider.Vault = &p
		S.Spec.Provider = &provider
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
	//	newpath := strings.Replace(path, "input", "output", 1)
	//	file, err := os.Create(newpath)
	if err != nil {
		return err
	}
	//	defer file.Close()
	//	file.Write(dat)
	//	fmt.Printf("File %s converted and available at %s\n", path, newpath)
	return nil
}

// Helper function for initial developments
func ParseKes(path string) {
	err := filepath.Walk(path, do_the_thing)
	if err != nil {
		log.Fatal("Something went wrong!\n%v\n", err)
		return
	}
}

// Helper function for initial developments
func main() {
	ParseKes("../test/input/")
}
