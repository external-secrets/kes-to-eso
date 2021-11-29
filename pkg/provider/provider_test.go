package provider

import (
	"context"
	"fmt"
	"kestoeso/pkg/apis"
	"kestoeso/pkg/utils"
	"reflect"
	"testing"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"

	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func TestGetSecretValue(t *testing.T) {
	ctx := context.TODO()
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("secret"),
		},
	}
	faker := testclient.NewSimpleClientset(&secret)
	opt := apis.KesToEsoOptions{}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.GetSecretValue(ctx, "test", "key", "default")
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	if ans != "secret" {
		t.Errorf("want secret got %v", ans)
	}
}

func TestGetServiceAccount(t *testing.T) {
	ctx := context.TODO()
	expectSuccess := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sa",
			Namespace: "default",
			Annotations: map[string]string{
				"a.annotation":        "false",
				"an.other/annotation": "something",
			},
		},
	}
	expectFailure := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sa2",
			Namespace: "default",
			Annotations: map[string]string{
				"b.annotation":        "false",
				"an.other/annotation": "something",
			},
		},
	}
	faker := testclient.NewSimpleClientset(&expectSuccess, &expectFailure)
	ns := "default"
	saSelector := esmeta.ServiceAccountSelector{Name: "sa", Namespace: &ns}
	client := KesToEsoClient{
		Client:  faker,
		Options: &apis.KesToEsoOptions{},
	}
	sa, err := client.GetServiceAccountIfAnnotationExists(ctx, "a.annotation", &saSelector)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	if !reflect.DeepEqual(sa, &expectSuccess) {
		t.Errorf("want %v got %v", &expectSuccess, sa)
	}
	saSelector = esmeta.ServiceAccountSelector{Name: "sa2", Namespace: &ns}
	_, err = client.GetServiceAccountIfAnnotationExists(ctx, "a.annotation", &saSelector)
	if err != nil {
		errmsg := fmt.Sprintf("%v", err)
		if errmsg != "annotation key absent in service account" {
			t.Errorf("Want annotation error got %v", errmsg)
		}
	}
}

func TestAWSInstall(t *testing.T) {
	ctx := context.TODO()
	deploymentWithSecretRef := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets",
			Namespace: "kes-ns",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "kes",
							Env: []corev1.EnvVar{
								{
									Name: "AWS_ACCESS_KEY_ID",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "aws-secret",
											},
											Key: "access-key-id",
										},
									}},
								{Name: "AWS_SECRET_ACCESS_KEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "aws-secret",
											},
											Key: "secret-access-key",
										},
									}},
							}},
					},
				},
			},
		},
	}
	base := utils.NewSecretStore(false)
	p := api.AWSProvider{}
	p.Service = api.AWSServiceSecretsManager
	prov := api.SecretStoreProvider{}
	prov.AWS = &p
	base.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset(&deploymentWithSecretRef)
	opt := apis.KesToEsoOptions{
		Namespace:       "kes-ns",
		ContainerName:   "kes",
		DeploymentName:  "kubernetes-external-secrets",
		ToStdout:        true,
		TargetNamespace: "",
	}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.InstallAWSSecrets(ctx, base)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	want_ns := "kes-ns"
	want_key := esmeta.SecretKeySelector{
		Name:      "aws-secret",
		Namespace: &want_ns,
		Key:       "access-key-id",
	}
	want_secret := esmeta.SecretKeySelector{
		Name:      "aws-secret",
		Namespace: &want_ns,
		Key:       "secret-access-key",
	}
	got_key := ans.Spec.Provider.AWS.Auth.SecretRef.AccessKeyID
	got_secret := ans.Spec.Provider.AWS.Auth.SecretRef.SecretAccessKey
	if !reflect.DeepEqual(want_key, got_key) {
		t.Errorf("want %v got %v", want_key, got_key)
	}
	if !reflect.DeepEqual(want_secret, got_secret) {
		t.Errorf("want %v got %v", want_secret, got_secret)
	}
}

func TestGCPInstall(t *testing.T) {
	ctx := context.TODO()
	deploymentWithSecretRef := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets",
			Namespace: "kes-ns",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "kes",
							Env: []corev1.EnvVar{
								{
									Name:  "GOOGLE_APPLICATION_CREDENTIALS",
									Value: "/path/to/gcp-creds.json"},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "a-name",
									MountPath: "/path/to",
								}}},
					},
					Volumes: []corev1.Volume{
						{
							Name: "a-name",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "gcp-secret",
								},
							},
						},
					},
				},
			},
		},
	}
	base := utils.NewSecretStore(false)
	p := api.GCPSMProvider{}
	prov := api.SecretStoreProvider{}
	prov.GCPSM = &p
	base.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset(&deploymentWithSecretRef)
	opt := apis.KesToEsoOptions{
		Namespace:       "kes-ns",
		ContainerName:   "kes",
		DeploymentName:  "kubernetes-external-secrets",
		ToStdout:        true,
		TargetNamespace: "",
	}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.InstallGCPSMSecrets(ctx, base)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	want_ns := "kes-ns"
	want_key := esmeta.SecretKeySelector{
		Name:      "gcp-secret",
		Namespace: &want_ns,
		Key:       "gcp-creds.json",
	}
	got_key := ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey
	if !reflect.DeepEqual(want_key, got_key) {
		t.Errorf("want %v got %v", want_key, got_key)
	}
}

func TestAzureInstall(t *testing.T) {
	ctx := context.TODO()
	deploymentWithSecretRef := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets",
			Namespace: "kes-ns",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "kes",
							Env: []corev1.EnvVar{
								{
									Name:  "AZURE_TENANT_ID",
									Value: "tenant",
								},
								{
									Name: "AZURE_CLIENT_ID",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "azure-secret",
											},
											Key: "client",
										},
									}},
								{
									Name: "AZURE_CLIENT_SECRET",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "azure-secret",
											},
											Key: "secret",
										},
									}}}},
					},
				},
			},
		},
	}
	base := utils.NewSecretStore(false)
	p := api.AzureKVProvider{}
	prov := api.SecretStoreProvider{}
	prov.AzureKV = &p
	base.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset(&deploymentWithSecretRef)
	opt := apis.KesToEsoOptions{
		Namespace:       "kes-ns",
		ContainerName:   "kes",
		DeploymentName:  "kubernetes-external-secrets",
		ToStdout:        true,
		TargetNamespace: "",
	}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.InstallAzureKVSecrets(ctx, base)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	want_ns := "kes-ns"
	want_key := esmeta.SecretKeySelector{
		Name:      "azure-secret",
		Namespace: &want_ns,
		Key:       "client",
	}
	want_secret := esmeta.SecretKeySelector{
		Name:      "azure-secret",
		Namespace: &want_ns,
		Key:       "secret",
	}
	got_key := *ans.Spec.Provider.AzureKV.AuthSecretRef.ClientID
	got_secret := *ans.Spec.Provider.AzureKV.AuthSecretRef.ClientSecret
	if !reflect.DeepEqual(want_key, got_key) {
		t.Errorf("want %v got %v - %v x %v", want_key, got_key, *want_secret.Namespace, *got_key.Namespace)
	}
	if !reflect.DeepEqual(want_secret, got_secret) {
		t.Errorf("want %v got %v", want_secret, got_secret)
	}
	want_ten := "tenant"
	if *ans.Spec.Provider.AzureKV.TenantID != want_ten {
		t.Errorf("want tenant got %v", *ans.Spec.Provider.AzureKV.TenantID)
	}
}

func TestIBMInstall(t *testing.T) {
	ctx := context.TODO()
	deploymentWithSecretRef := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets",
			Namespace: "kes-ns",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "kes",
							Env: []corev1.EnvVar{
								{
									Name:  "IBM_CLOUD_SECRETS_MANAGER_API_ENDPOINT",
									Value: "tenant",
								},
								{
									Name: "IBM_CLOUD_SECRETS_MANAGER_API_APIKEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "ibm-secret",
											},
											Key: "secret",
										},
									}},
							}},
					},
				},
			},
		},
	}
	base := utils.NewSecretStore(false)
	p := api.IBMProvider{}
	prov := api.SecretStoreProvider{}
	prov.IBM = &p
	base.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset(&deploymentWithSecretRef)
	opt := apis.KesToEsoOptions{
		Namespace:       "kes-ns",
		ContainerName:   "kes",
		DeploymentName:  "kubernetes-external-secrets",
		ToStdout:        true,
		TargetNamespace: "",
	}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.InstallIBMSecrets(ctx, base)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	want_ns := "kes-ns"
	want_secret := esmeta.SecretKeySelector{
		Name:      "ibm-secret",
		Namespace: &want_ns,
		Key:       "secret",
	}
	got_secret := ans.Spec.Provider.IBM.Auth.SecretRef.SecretAPIKey
	if !reflect.DeepEqual(want_secret, got_secret) {
		t.Errorf("want %v got %v", want_secret, got_secret)
	}
	want_url := "tenant"
	if *ans.Spec.Provider.IBM.ServiceURL != want_url {
		t.Errorf("want %v got %s", want_url, *ans.Spec.Provider.IBM.ServiceURL)
	}
}

func TestVaultInstall(t *testing.T) {
	ctx := context.TODO()
	want_path := "kuber-path"
	want_role := "kuber-role"
	want_url := "https://localhost"
	deploymentWithSecretRef := appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes-external-secrets",
			Namespace: "kes-ns",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "kes",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: want_url,
								},
								{
									Name:  "DEFAULT_VAULT_MOUNT_POINT",
									Value: want_path,
								},
								{
									Name:  "DEFAULT_VAULT_ROLE",
									Value: want_role,
								},
							}},
					},
				},
			},
		},
	}
	base := utils.NewSecretStore(false)
	p := api.VaultProvider{}
	prov := api.SecretStoreProvider{}
	prov.Vault = &p
	base.Spec.Provider = &prov
	faker := testclient.NewSimpleClientset(&deploymentWithSecretRef)
	opt := apis.KesToEsoOptions{
		Namespace:       "kes-ns",
		ContainerName:   "kes",
		DeploymentName:  "kubernetes-external-secrets",
		ToStdout:        true,
		TargetNamespace: "",
	}
	c := KesToEsoClient{
		Client:  faker,
		Options: &opt,
	}
	ans, err := c.InstallVaultSecrets(ctx, base)
	if err != nil {
		t.Errorf("want success got %v", err)
	}
	got_role := ans.Spec.Provider.Vault.Auth.Kubernetes.Role
	got_path := ans.Spec.Provider.Vault.Auth.Kubernetes.Path
	if !reflect.DeepEqual(want_path, got_path) {
		t.Errorf("want %v got %v", want_path, got_path)
	}
	if want_role != got_role {
		t.Errorf("want %v got %s", want_role, got_role)
	}
	got_url := ans.Spec.Provider.Vault.Server
	if want_url != got_url {
		t.Errorf("want %v got %s", want_url, got_url)
	}
}
