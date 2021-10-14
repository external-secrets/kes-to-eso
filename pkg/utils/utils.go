package utils

import (
	"fmt"
	"kestoeso/pkg/apis"
	"os"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	//	"k8s.io/client-go/util/homedir"
	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	//	"k8s.io/client-go/tools/clientcmd"
	yaml "sigs.k8s.io/yaml"
)

func IsKES(K apis.KESExternalSecret) bool {
	return K.Kind == "ExternalSecret" && K.ApiVersion == "kubernetes-client.io/v1"
}

func NewSecretStore(secretStore bool) api.SecretStore {
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

func WriteYaml(S interface{}, filepath string, to_stdout bool) error {
	dat, err := yaml.Marshal(S)
	if err != nil {
		return err
	}
	if to_stdout {
		fmt.Println(string(dat))
		NewYaml()
	} else {
		err = os.WriteFile(filepath, dat, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func UpdateOrCreateSecret(secret *corev1.Secret, essecret *esmeta.SecretKeySelector, secretValue string) (*corev1.Secret, error) {
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
func NewYaml() {
	fmt.Println("---")
}
