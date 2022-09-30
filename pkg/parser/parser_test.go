package parser

import (
	"context"
	"fmt"
	"kestoeso/pkg/apis"
	"kestoeso/pkg/provider"
	"kestoeso/pkg/utils"
	"os"
	"reflect"
	"testing"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
	yaml "sigs.k8s.io/yaml"
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
	ctx := context.TODO()
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
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindAWSPSProvider(t *testing.T) {
	ctx := context.TODO()
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
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindGCPProvider(t *testing.T) {
	ctx := context.TODO()
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType: "gcpSecretsManager",
			ProjectID:   "my-project",
			DataFrom: []string{
				"path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "kv/demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "kv/demo-service/credentials",
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
	p := api.GCPSMProvider{}
	p.ProjectID = "my-project"
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.GCPSM = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindIBMProvider(t *testing.T) {
	ctx := context.TODO()
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType: "ibmcloudSecretsManager",
			DataFrom: []string{
				"path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "demo-service/credentials",
					Name:         "password",
					SecretType:   "username_password",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "demo-service/credentials",
					Name:         "username",
					SecretType:   "username_password",
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
	p := api.IBMProvider{}
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.IBM = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindAzureProvider(t *testing.T) {
	ctx := context.TODO()
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "azureKeyVault",
			VaultMountPoint: "",
			VaultRole:       "",
			ProjectID:       "",
			KeyVaultName:    "my-vault",
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
	p := api.AzureKVProvider{}
	url := "https://my-vault.vault.azure.net"
	p.VaultURL = &url
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.AzureKV = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

}

func TestBindVaultProvider(t *testing.T) {
	ctx := context.TODO()
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aws-secretsmanager",
			Namespace: "kes-ns",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "vault",
			VaultMountPoint: "kubernetes",
			VaultRole:       "my-role",
			KvVersion:       2,
			DataFrom: []string{
				"kv/demo-service/credentials",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "kv/demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "kv/demo-service/credentials",
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
	p := api.VaultProvider{}
	kubeauth := api.VaultKubernetesAuth{
		Path: "kubernetes",
		Role: "my-role",
	}
	auth := api.VaultAuth{}
	p.Version = api.VaultKVStoreV2
	p.Path = "kv"
	auth.Kubernetes = &kubeauth
	p.Auth = auth
	prov := api.SecretStoreProvider{}
	want.ObjectMeta.Namespace = "kes-ns"
	prov.Vault = &p
	want.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	got, _ := bindProvider(ctx, S, K, &c)
	// Forcing name to be equal, since it's randomly generated
	want.ObjectMeta.Name = got.ObjectMeta.Name
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v got %v", want, got)
	}

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
				{
					Key:          "demo-service/credentials",
					Name:         "username",
					SecretType:   "username_password",
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
				{
					SecretKey: "username",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "username_password/demo-service/credentials",
						Property: "username",
					},
				},
			},
		},
	}
	if !assert.Equal(t, want, got) {
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

func TestParseSpecifics(t *testing.T) {
	K := apis.KESExternalSecret{
		Kind:       "ExternalSecret",
		ApiVersion: "kubernetes-client.io/v1",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault",
			Namespace: "default",
		},
		Spec: apis.KESExternalSecretSpec{
			BackendType:     "vault",
			VaultMountPoint: "kubernetes",
			VaultRole:       "role",
			KvVersion:       2,
			Region:          "",
			DataFrom: []string{
				"vault-name/data/path/to/data",
			},
			Data: []apis.KESExternalSecretData{
				{
					Key:          "vault-name/data/demo-service/credentials",
					Name:         "password",
					SecretType:   "",
					Property:     "password",
					Recursive:    "",
					Path:         "",
					VersionStage: "",
					IsBinary:     false,
				},
				{
					Key:          "vault-name/data/demo-service/credentials",
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
	E := api.ExternalSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault",
			Namespace: "default",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExternalSecret",
			APIVersion: "external-secrets.io/v1alpha1",
		},
		Spec: api.ExternalSecretSpec{
			Target: api.ExternalSecretTarget{
				Name:     "vault",
				Template: &api.ExternalSecretTemplate{},
			},
			DataFrom: []api.ExternalSecretDataRemoteRef{
				{Key: "vault-name/data/path/to/data"},
			},
			Data: []api.ExternalSecretData{
				{
					SecretKey: "password",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "vault-name/data/demo-service/credentials",
						Property: "password",
					},
				},
				{
					SecretKey: "username",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "vault-name/data/demo-service/credentials",
						Property: "username",
					},
				},
			},
		},
	}
	got, err := parseSpecifics(K, E)
	if err != nil {
		t.Errorf("want success got err: %v", err)
	}

	want := api.ExternalSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault",
			Namespace: "default",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExternalSecret",
			APIVersion: "external-secrets.io/v1alpha1",
		},
		Spec: api.ExternalSecretSpec{
			Target: api.ExternalSecretTarget{
				Name:     "vault",
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
	if !assert.Equal(t, want, got) {
		t.Errorf("want %v got %v", want, got)
	}
	bad := api.ExternalSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault",
			Namespace: "default",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExternalSecret",
			APIVersion: "external-secrets.io/v1alpha1",
		},
		Spec: api.ExternalSecretSpec{
			Target: api.ExternalSecretTarget{
				Name:     "vault",
				Template: &api.ExternalSecretTemplate{},
			},
			DataFrom: []api.ExternalSecretDataRemoteRef{
				{Key: "path/to/data"},
			},
			Data: []api.ExternalSecretData{
				{
					SecretKey: "password",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "vault-name/demo-service/credentials",
						Property: "password",
					},
				},
				{
					SecretKey: "username",
					RemoteRef: api.ExternalSecretDataRemoteRef{
						Key:      "vault-name/demo-service/credentials",
						Property: "username",
					},
				},
			},
		},
	}
	_, err = parseSpecifics(K, bad)
	if err.Error() != "secret key not compatible with kv2 format (<vault>/data/<path>/<to>/<secret>)" {
		t.Errorf("want 'secret key not compatible with kv2 format (<vault>/data/<path>/<to>/<secret>)' got : %v", err)
	}
}

type rootStruct struct {
	name                    string
	golden                  string
	input                   apis.KESExternalSecret
	secretStoreWants        *api.SecretStore
	clusterSecretStoreWants *api.ClusterSecretStore
	externalSecretWants     api.ExternalSecret
}

func loadInput(cases []rootStruct) ([]rootStruct, error) {
	ans := cases
	for idx, test := range cases {
		kes, err := readKESFromFile(fmt.Sprintf("testdata/%v.golden", test.golden))
		if err != nil {
			return cases, err
		}
		ans[idx].input = kes
	}
	return ans, nil
}

func readSSFromFile(file string) (api.SecretStore, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return api.SecretStore{}, err
	}
	var K = api.SecretStore{}
	err = yaml.Unmarshal(dat, &K)
	if err != nil {
		return api.SecretStore{}, err
	}
	return K, nil
}

func readCSSFromFile(file string) (api.ClusterSecretStore, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return api.ClusterSecretStore{}, err
	}
	var K = api.ClusterSecretStore{}
	err = yaml.Unmarshal(dat, &K)
	if err != nil {
		return api.ClusterSecretStore{}, err
	}
	return K, nil
}

func readESFromFile(file string) (api.ExternalSecret, error) {
	dat, err := os.ReadFile(file)
	if err != nil {
		return api.ExternalSecret{}, err
	}
	var K = api.ExternalSecret{}
	err = yaml.Unmarshal(dat, &K)
	if err != nil {
		return api.ExternalSecret{}, err
	}
	return K, nil
}

func loadWants(cases []rootStruct) ([]rootStruct, error) {
	ans := cases
	for idx, test := range cases {
		es, err := readESFromFile(fmt.Sprintf("testdata/es_%v.golden", test.golden))
		if err != nil {
			return cases, err
		}
		ans[idx].externalSecretWants = es
		ss, err_ss := readSSFromFile(fmt.Sprintf("testdata/ss_%v.golden", test.golden))
		css, err_css := readCSSFromFile(fmt.Sprintf("testdata/css_%v.golden", test.golden))
		if err_ss != nil && err_css != nil {
			return cases, err
		}
		if err_ss == nil {
			ans[idx].secretStoreWants = &ss
		}
		if err_css == nil {
			ans[idx].clusterSecretStoreWants = &css
		}
	}
	return ans, nil
}
func TestRoot(t *testing.T) {
	ctx := context.TODO()
	testCases := []rootStruct{
		{
			name:   "aws-secretsmanager",
			golden: "aws-secretsmanager",
		},
	}
	testCases, err := loadInput(testCases)
	if err != nil {
		t.Fatalf("ERROR! %v", err)
	}
	_, err = loadWants(testCases)
	if err != nil {
		t.Fatalf("ERROR! %v", err)
	}
	options := apis.KesToEsoOptions{
		Namespace:      "",
		ContainerName:  "",
		DeploymentName: "",
		InputPath:      "testdata",
		ToStdout:       true,
	}
	faker := testclient.NewSimpleClientset()
	c := provider.KesToEsoClient{
		Client:  faker,
		Options: &options,
	}
	resp := Root(ctx, &c)
	for idx, testcase := range testCases {
		assert.Equal(t, testcase.externalSecretWants, resp[idx].Es)
		if testcase.secretStoreWants != nil {
			assert.Equal(t, *testcase.secretStoreWants, resp[idx].Ss)
			assert.Equal(t, testcase.secretStoreWants.Spec.Provider, resp[idx].Ss.Spec.Provider)
		}
		if testcase.clusterSecretStoreWants != nil {
			assert.Equal(t, *testcase.clusterSecretStoreWants, resp[idx].Ss)
			assert.Equal(t, testcase.clusterSecretStoreWants.Spec.Provider, resp[idx].Ss.Spec.Provider)
		}
	}

}
