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

func (c ApplyClient) updateSingleSecret(ctx context.Context, namespace string, secret *corev1.Secret) (bool, error) {
	for idx, owner := range secret.OwnerReferences {
		if owner.APIVersion == c.Options.TargetOwner && owner.Kind == "ExternalSecret" {
			log.Debugf("Secret %v/%v matches owner %v", secret.Namespace, secret.Name, c.Options.TargetOwner)
			tmpSecret := secret.DeepCopy()
			if len(tmpSecret.OwnerReferences) > 1 {
				tmpSecret.OwnerReferences[idx] = tmpSecret.OwnerReferences[len(tmpSecret.OwnerReferences)-1]
				tmpSecret.OwnerReferences = tmpSecret.OwnerReferences[:len(tmpSecret.OwnerReferences)-2]

			} else {
				tmpSecret.OwnerReferences = []metav1.OwnerReference{}
			}
			_, err := c.Client.CoreV1().Secrets(namespace).Update(ctx, tmpSecret, metav1.UpdateOptions{})
			if err != nil {
				return false, err
			}
			log.Infof("Secret %v/%v updated successfully", secret.Namespace, secret.Name)
			return true, nil
		}
	}
	return false, nil
}

func (c ApplyClient) UpdateSecretsFromAll(ctx context.Context, secrets []string) (int, error) {
	secretMap := mapSecrets(secrets)
	secretList, err := c.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, secret := range secretList.Items {
		_, ok := secretMap[secret.Name]
		if ok {
			log.Debugf("Reading secret %v/%v", secret.Namespace, secret.Name)
			update, err := c.updateSingleSecret(ctx, secret.Namespace, &secret)
			if err != nil {
				return count, err
			}
			if update {
				count = count + 1
			}
		}
	}
	return count, nil
}

func (c ApplyClient) UpdateSecretsFromNamespace(ctx context.Context, secrets []string) (int, error) {
	secretMap := mapSecrets(secrets)
	secretList, err := c.Client.CoreV1().Secrets(c.Options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, secret := range secretList.Items {
		_, ok := secretMap[secret.Name]
		if ok {
			log.Debugf("Reading secret %v/%v", secret.Namespace, secret.Name)
			update, err := c.updateSingleSecret(ctx, c.Options.Namespace, &secret)
			if err != nil {
				return count, err
			}
			if update {
				count = count + 1
			}
		}
	}
	return count, nil
}

func (c ApplyClient) UpdateAll(ctx context.Context) (int, error) {
	secretList, err := c.Client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, secret := range secretList.Items {
		log.Debugf("Reading secret %v/%v", secret.Namespace, secret.Name)
		update, err := c.updateSingleSecret(ctx, secret.Namespace, &secret)
		if err != nil {
			return count, err
		}
		if update {
			count = count + 1
		}
	}
	return count, nil
}

func (c ApplyClient) UpdateAllFromNamespace(ctx context.Context) (int, error) {
	secretList, err := c.Client.CoreV1().Secrets(c.Options.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, secret := range secretList.Items {
		log.Debugf("Reading secret %v/%v", secret.Namespace, secret.Name)
		update, err := c.updateSingleSecret(ctx, c.Options.Namespace, &secret)
		if err != nil {
			return count, err
		}
		if update {
			count = count + 1
		}
	}
	return count, nil
}

func Root(ctx context.Context, client *ApplyClient, secrets []string) error {
	var count int
	var err error
	if client.Options.AllSecrets && client.Options.AllNamespaces {
		count, err = client.UpdateAll(ctx)
	} else if client.Options.AllSecrets {
		count, err = client.UpdateAllFromNamespace(ctx)
	} else if client.Options.AllNamespaces {
		count, err = client.UpdateSecretsFromAll(ctx, secrets)
	} else {
		count, err = client.UpdateSecretsFromNamespace(ctx, secrets)
	}
	log.Infof("Updated %v secrets", count)
	return err
}
