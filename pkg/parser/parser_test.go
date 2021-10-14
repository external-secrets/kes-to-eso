package parser

import (
	"kestoeso/pkg/apis"
	"kestoeso/pkg/provider"
	"kestoeso/pkg/utils"
	"reflect"
	"testing"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func TestNewEsoSecret(t *testing.T) {
	S := NewESOSecret()
	if S.TypeMeta.Kind != "ExternalSecret" {
		t.Errorf("want ExternalSecret got %v", S.TypeMeta.Kind)
	}
	if S.TypeMeta.APIVersion != "external-secrets.io/v1alpha1" {
		t.Errorf("want external-secrets.io/v1alpha1 got %v", S.TypeMeta.APIVersion)
	}
}

func TestBindAWSSMProvider(t *testing.T) {
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "secretsManager",
			VaultMountPoint: "",
			VaultRole:       "",
			ProjectID:       "",
			RoleArn:         "arn:aws:iam::123412341234:role/let-other-account-access-secrets",
			Region:          "eu-west-1",
			DataFrom: []string{
				"path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "demo-service/credentials",
					Name:         "username",
					SecretType:   "",
					Property:     "username",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
			},
		},
	}
	S := utils.NewSecretStore(false)
	want := utils.NewSecretStore(false)
	p := api.AWSProvider{}
	p.Service = api.AWSServiceSecretsManager
	p.Role = "arn:aws:iam::123412341234:role/let-other-account-access-secrets"
	p.Region = "eu-west-1"
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.AWS = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindAWSPSProvider(t *testing.T) {
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "systemManager",
			VaultMountPoint: "",
			VaultRole:       "",
			ProjectID:       "",
			RoleArn:         "arn:aws:iam::123412341234:role/let-other-account-access-secrets",
			Region:          "eu-west-1",
			DataFrom: []string{
				"path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "demo-service/credentials",
					Name:         "username",
					SecretType:   "",
					Property:     "username",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
			},
		},
	}
	S := utils.NewSecretStore(false)
	want := utils.NewSecretStore(false)
	p := api.AWSProvider{}
	p.Service = api.AWSServiceParameterStore
	p.Role = "arn:aws:iam::123412341234:role/let-other-account-access-secrets"
	p.Region = "eu-west-1"
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.AWS = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindGCPProvider(t *testing.T) {

}

func TestBindIBMProvider(t *testing.T) {

}

func TestBindAzureProvider(t *testing.T) {

}

func TestBindVaultProvider(t *testing.T) {

}

func TestParseGenerals(t *testing.T) {
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "default",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "secretsManager",
			VaultMountPoint: "",
			VaultRole:       "",
			ProjectID:       "eu-west-1",
			RoleArn:         "arn:aws:iam::123412341234:role/let-other-account-access-secrets",
			Region:          "",
			DataFrom: []string{
				"path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "demo-service/credentials",
					Name:         "username",
					SecretType:   "",
					Property:     "username",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
			},
		},
	}
	opt := apis.KesToEsoOptions{}
	E := NewESOSecret()
	got, err := parseGenerals(K, E, &opt)
	if err != nil {
		t.Errorf("want success got err: %v", err)
	}
	want := api.ExternalSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "default",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExternalSecret",
			APIVersion: "external-secrets.io/v1alpha1",
		},
		Spec: api.ExternalSecretSpec{
			Target: api.ExternalSecretTarget{
				Name:     "aws-secretsmanager",
				Template: &api.ExternalSecretTemplate{},
			},
			DataFrom: []api.ExternalSecretDataRemoteRef{
				{Key: "path/to/data"},
			},
			Data: []api.ExternalSecretData{
				{
					SecretKey: "password",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "demo-service/credentials",
						Property: "password",
					},
				},
				{
					SecretKey: "username",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "demo-service/credentials",
						Property: "username",
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v - %v x %v", want, got, want.Spec.Target.Template, got.Spec.Target.Template)
	}
}

func TestLinkSecretStore(t *testing.T) {
	S := api.SecretStore{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-secret-store",
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "SecretStore",
		},
	}
	E := NewESOSecret()
	got := linkSecretStore(E, S)
	want := NewESOSecret()
	want.Spec.SecretStoreRef.Name = "some-secret-store"
	want.Spec.SecretStoreRef.Kind = "SecretStore"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %v got %v", want, got)
	}
}
