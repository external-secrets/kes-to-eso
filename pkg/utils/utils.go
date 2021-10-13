package utils

import (
	"context"
	"errors"
	"fmt"
	"kestoeso/pkg/apis"
	"os"

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

func InitKubeConfig() (*kubernetes.Clientset, error) {
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

func IsKES(K apis.KESExternalSecret) bool {
	return K.Kind == "ExternalSecret" && K.ApiVersion == "kubernetes-client.io/v1"
}

func GetSecretValue(name string, key string, namespace string) (string, error) {
	clientset, err := InitKubeConfig()
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

func GetServiceAccountIfAnnotationExists(key string, sa *esmeta.ServiceAccountSelector) (*corev1.ServiceAccount, error) {
	clientset, err := InitKubeConfig()
	if err != nil {
		return nil, err
	}
	s, err := clientset.CoreV1().ServiceAccounts(*sa.Namespace).Get(context.TODO(), sa.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	_, found := s.Annotations[key]
	if found {
		return s, nil
	} else {
		return nil, errors.New("annotation key absent in service account")
	}
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

func NewYaml() {
	fmt.Println("---")
}
