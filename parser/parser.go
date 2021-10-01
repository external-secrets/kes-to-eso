package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	yaml "gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KESExternalSecret struct {
	Meta       metav1.TypeMeta   `yaml:",inline"`
	ObjectMeta metav1.ObjectMeta `yaml:"metadata"`
	Spec       struct {
		BackendType     string
		VaultMountPoint string
		VaultRole       string
		KvVersion       int
		RoleArn         string
		Region          string
		DataFrom        []string
		Data            []struct {
			Key          string
			Name         string
			Property     string
			Recursive    string
			Path         string
			VersionStage string
			Version      string
			IsBinary     bool
			SecretType   string
		}
		Template map[string]interface{}
	}
}

func readKES(file string) (KESExternalSecret, error) {
	dat, err := os.ReadFile(file)
	T := KESExternalSecret{}
	yaml.Unmarshal(dat, &T)
	if err != nil {
		return KESExternalSecret{}, err
	}
	return T, nil
}

func newESOSecret() api.ExternalSecret {
	return api.ExternalSecret{}
}

func parseGenerals(K KESExternalSecret, E api.ExternalSecret) (api.ExternalSecret, error) {
	secret := E
	secret.ObjectMeta = K.ObjectMeta
	secret.Spec.Target.Name = K.ObjectMeta.Name // Inherits default in KES, so we should do the same approach here
	var refKey string
	for _, kesSecretData := range K.Spec.Data {
		if kesSecretData.SecretType != "" {
			refKey = kesSecretData.SecretType + "/" + kesSecretData.Key
		} else {
			refKey = kesSecretData.Key
		}
		esoRemoteRef := api.ExternalSecretDataRemoteRef{Key: refKey, Property: kesSecretData.Property, Version: kesSecretData.Version}
		esoSecretData := api.ExternalSecretData{SecretKey: kesSecretData.Name, RemoteRef: esoRemoteRef}
		secret.Spec.Data = append(secret.Spec.Data, esoSecretData)
	}
	return secret, nil

}

type NotSupportedProvider struct{}

// Method to parse store specifics information from a KES External Secret
var ProviderMap = map[string]interface{}{
	"akeyless":               NotSupportedProvider{},
	"alicloudSecretsManager": NotSupportedProvider{}, // TODO there is a definition but not foundable by go mod...
	"secretsManager":         api.AWSProvider{},
	"systemManager":          api.AWSProvider{},
	"azureKeyVault":          api.AzureKVProvider{},
	"gcpSecretsManager":      api.GCPSMProvider{},
	"ibmcloudSecretsManager": api.IBMProvider{},
	"vault":                  api.VaultProvider{},
}

func parseStoreSpecifics(K KESExternalSecret, S api.SecretStore) (store api.SecretStore) {
	return api.SecretStore{}
}

func parseClusterStoreSpecifics(K KESExternalSecret, E api.ExternalSecret) (store api.SecretStore) {
	return api.SecretStore{}
}

func isKES(K KESExternalSecret) bool {
	return K.Meta.Kind == "ExternalSecret"
}

// all below are helper function for initial development. They are going to be removed afterwards

// Helper function for initial developments
func list(path string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}
	fmt.Printf("found path %v\n", path)
	if info.IsDir() {
		return nil
	}
	K, err := readKES(path)
	if err != nil {
		return err
	}
	if !isKES(K) {
		fmt.Printf("%s is not a KES file.\n", path)
		return nil
	}
	E, err := parseGenerals(K, api.ExternalSecret{})
	if err != nil {
		return err
	}
	newpath := strings.Replace(path, "input", "output", 1)
	file, err := os.Create(newpath)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := yaml.NewEncoder(file)
	encoder.Encode(E)
	fmt.Printf("File %s converted and available at %s\n", path, newpath)
	return nil
}

// Helper function for initial developments
func ParseKes(path string) {
	err := filepath.Walk(path, list)
	if err != nil {
		log.Fatal("Something went wrong!\n%v\n", err)
		return
	}
}

// Helper function for initial developments
func main() {
	ParseKes("../test/input")
}
