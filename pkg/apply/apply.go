package apply

import (
	"context"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ApplyOptions struct {
	Namespace     string
	AllNamespaces bool
	AllSecrets    bool
	Name          string
	TargetOwner   string
}

func NewApplyOptions() *ApplyOptions {
	a := ApplyOptions{
		Namespace:     "default",
		AllNamespaces: false,
		AllSecrets:    false,
		Name:          "",
		TargetOwner:   "kubernetes-external-secrets",
	}
	return &a
}

type ApplyClient struct {
	Options *ApplyOptions
	Client  kubernetes.Interface
}

func mapSecrets(secrets []string) map[string]string {
	ans := map[string]string{}
	for _, secret := range secrets {
		ans[secret] = secret
	}
	return ans
}

func (c ApplyClient) updateSingleSecret(ctx context.Context, namespace string, secret *corev1.Secret) error {
	for idx, owner := range secret.OwnerReferences {
		if owner.APIVersion == c.Options.TargetOwner && owner.Kind == "ExternalSecret" {
			log.Infof("Secret %v/%v matches owner %v", secret.Namespace, secret.Name, c.Options.TargetOwner)
			tmpSecret := secret.DeepCopy()
			if len(tmpSecret.OwnerReferences) > 1 {
				tmpSecret.OwnerReferences[idx] = tmpSecret.OwnerReferences[len(tmpSecret.OwnerReferences)-1]
				tmpSecret.OwnerReferences = tmpSecret.OwnerReferences[:len(tmpSecret.OwnerReferences)-2]

			} else {
				tmpSecret.OwnerReferences = []metav1.OwnerReference{}
			}
			_, err := c.Client.CoreV1().Secrets(namespace).Update(ctx, tmpSecret, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			log.Infof("Secret %v/%v updated successfully", secret.Namespace, secret.Name)
		}
	}
	return nil
}

func (c ApplyClient) UpdateSecretsFromAll(ctx context.Context, secrets []string) error {
	secretMap := mapSecrets(secrets)
	secretList, err := c.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, secret := range secretList.Items {
		_, ok := secretMap[secret.Name]
		if ok {
			log.Infof("Reading secret %v/%v", secret.Namespace, secret.Name)
			err := c.updateSingleSecret(ctx, secret.Namespace, &secret)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c ApplyClient) UpdateSecretsFromNamespace(ctx context.Context, secrets []string) error {
	secretMap := mapSecrets(secrets)
	secretList, err := c.Client.CoreV1().Secrets(c.Options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, secret := range secretList.Items {
		_, ok := secretMap[secret.Name]
		if ok {
			log.Infof("Reading secret %v/%v", secret.Namespace, secret.Name)
			err := c.updateSingleSecret(ctx, c.Options.Namespace, &secret)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c ApplyClient) UpdateAll(ctx context.Context) error {
	secretList, err := c.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, secret := range secretList.Items {
		log.Infof("Reading secret %v/%v", secret.Namespace, secret.Name)
		err := c.updateSingleSecret(ctx, secret.Namespace, &secret)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c ApplyClient) UpdateAllFromNamespace(ctx context.Context) error {
	secretList, err := c.Client.CoreV1().Secrets(c.Options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, secret := range secretList.Items {
		log.Infof("Reading secret %v/%v", secret.Namespace, secret.Name)
		err := c.updateSingleSecret(ctx, c.Options.Namespace, &secret)
		if err != nil {
			return err
		}
	}
	return nil
}

func Root(ctx context.Context, client *ApplyClient, secrets []string) error {
	if client.Options.AllSecrets && client.Options.AllNamespaces {
		err := client.UpdateAll(ctx)
		return err
	} else if client.Options.AllSecrets {
		err := client.UpdateAllFromNamespace(ctx)
		return err

	} else if client.Options.AllNamespaces {
		err := client.UpdateSecretsFromAll(ctx, secrets)
		return err

	} else {
		err := client.UpdateSecretsFromNamespace(ctx, secrets)
		return err
	}
}
