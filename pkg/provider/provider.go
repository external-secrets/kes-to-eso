package provider

import (
	"context"
	"errors"
	"fmt"
	"kestoeso/pkg/apis"
	"kestoeso/pkg/utils"
	"strings"

	api "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//	"k8s.io/client-go/util/homedir"
	//	"k8s.io/client-go/kubernetes"
	//	"k8s.io/client-go/rest"
	//	"k8s.io/client-go/tools/clientcmd"
)

func InstallAWSSecrets(S api.SecretStore, opt *apis.KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	clientset, err := utils.InitKubeConfig()
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
						newsecret, err = utils.UpdateOrCreateSecret(newsecret, &keySelector, env.Value)
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
						newsecret, err = utils.UpdateOrCreateSecret(newsecret, &secretSelector, env.Value)
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
		utils.WriteYaml(newsecret, secret_filename, target.ToStdout)
	}
	if awsSecretRef.AccessKeyID.Name == "" || awsSecretRef.SecretAccessKey.Name == "" {
		return S, errors.New("could not find aws credential information on kes deployment")
	}
	return ans, nil
}

func InstallVaultSecrets(S api.SecretStore, opt *apis.KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.VaultKubernetesAuth{}
	clientset, err := utils.InitKubeConfig()
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
						value, err := utils.GetSecretValue(name, key, target.Namespace)
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
						value, err := utils.GetSecretValue(name, key, target.Namespace)
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
						value, err := utils.GetSecretValue(name, key, target.Namespace)
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
		utils.WriteYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.Role == "" || authRef.Path == "" || ans.Spec.Provider.Vault.Server == "" {
		return ans, errors.New("credentials for vault not found in kes deployment")
	}
	return ans, nil
}

func InstallGCPSMSecrets(S api.SecretStore, opt *apis.KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	clientset, err := utils.InitKubeConfig()
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
	var secretName string
	volumes := deployment.Spec.Template.Spec.Volumes
	for _, volume := range volumes {
		if volume.Name == volumeName {
			secretName = volume.Secret.SecretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Name = secretName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Key = keyName
			ans.Spec.Provider.GCPSM.Auth.SecretRef.SecretAccessKey.Namespace = &target.Namespace
		}
	}
	if secretName == "" || keyName == "" {
		return ans, errors.New("credentials for gcp sm not found in kes deployment")
	}
	// if reflect.DeepEqual(ans, S) {
	// }
	return ans, nil
}

func InstallAzureKVSecrets(S api.SecretStore, opt *apis.KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.AzureKVAuth{}
	clientset, err := utils.InitKubeConfig()
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
						value, err := utils.GetSecretValue(name, key, target.Namespace)
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
						newsecret, err = utils.UpdateOrCreateSecret(newsecret, &clientSelector, env.Value)
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
						newsecret, err = utils.UpdateOrCreateSecret(newsecret, &secretSelector, env.Value)
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
		utils.WriteYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.ClientID == nil || authRef.ClientSecret == nil {
		return ans, errors.New("credentials for azure not found in kes deployment")
	}
	return ans, nil
}

func InstallIBMSecrets(S api.SecretStore, opt *apis.KesToEsoOptions) (api.SecretStore, error) {
	ans := S
	authRef := api.IBMAuth{}
	clientset, err := utils.InitKubeConfig()
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
						newsecret, err = utils.UpdateOrCreateSecret(newsecret, &secretSelector, env.Value)
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
						value, err := utils.GetSecretValue(name, key, target.Namespace)
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
		utils.WriteYaml(newsecret, secret_filename, target.ToStdout)
	}
	if authRef.SecretRef.SecretAPIKey.Name == "" {
		return ans, errors.New("credentials for ibm cloud not found in kes deployment. edit secretstore definitions before using it")
	}
	return ans, nil
}
