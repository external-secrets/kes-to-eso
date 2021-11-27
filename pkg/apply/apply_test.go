package apply

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

func createSecret(secretName string, secretNamespace string, OwnerType string) *corev1.Secret {
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind:       "ExternalSecret",
					APIVersion: OwnerType,
				},
			},
		},
	}
	return &secret
}
func TestUpdateSecretsFromAll(t *testing.T) {
	ctx := context.TODO()
	first := createSecret("secret", "one", "right")
	second := createSecret("secret", "two", "right")
	third := createSecret("secret-2", "two", "right")
	fourth := createSecret("secret-2", "one", "right")
	fifth := createSecret("fake", "one", "left")
	faker := testclient.NewSimpleClientset(first, second, third, fourth, fifth)
	options := NewApplyOptions()
	options.AllNamespaces = true
	options.TargetOwner = "right"
	client := ApplyClient{
		Client:  faker,
		Options: options,
	}
	targets := []string{"secret"}
	count, err := client.UpdateSecretsFromAll(ctx, targets)
	assert.Equal(t, 2, count)
	assert.NoError(t, err)
	targets = []string{"fake"}
	count, err = client.UpdateSecretsFromAll(ctx, targets)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestUpdateSecretsFromNamespace(t *testing.T) {
	ctx := context.TODO()
	first := createSecret("secret", "one", "right")
	second := createSecret("secret", "two", "right")
	third := createSecret("secret-2", "two", "right")
	fourth := createSecret("secret-2", "one", "right")
	fifth := createSecret("fake", "one", "left")
	faker := testclient.NewSimpleClientset(first, second, third, fourth, fifth)
	options := NewApplyOptions()
	options.AllNamespaces = false
	options.Namespace = "one"
	options.TargetOwner = "right"
	client := ApplyClient{
		Client:  faker,
		Options: options,
	}
	targets := []string{"secret"}
	count, err := client.UpdateSecretsFromNamespace(ctx, targets)
	assert.NoError(t, err)
	assert.Equal(t, count, 1)
	client.Options.Namespace = "two"
	targets = []string{"secret", "secret-2"}
	count, err = client.UpdateSecretsFromNamespace(ctx, targets)
	assert.NoError(t, err)
	assert.Equal(t, count, 2)
	targets = []string{"fake"}
	count, err = client.UpdateSecretsFromNamespace(ctx, targets)
	assert.NoError(t, err)
	assert.Equal(t, count, 0)

}

func TestUpdateAllFromNamespace(t *testing.T) {
	ctx := context.TODO()
	first := createSecret("secret", "one", "right")
	second := createSecret("secret", "two", "right")
	third := createSecret("secret-2", "two", "right")
	fourth := createSecret("secret-2", "one", "right")
	fifth := createSecret("fake", "one", "left")
	faker := testclient.NewSimpleClientset(first, second, third, fourth, fifth)
	options := NewApplyOptions()
	options.AllNamespaces = false
	options.AllSecrets = true
	options.Namespace = "one"
	options.TargetOwner = "right"
	client := ApplyClient{
		Client:  faker,
		Options: options,
	}
	count, err := client.UpdateAllFromNamespace(ctx)
	assert.NoError(t, err)
	assert.Equal(t, count, 2)
	client.Options.Namespace = "two"
	count, err = client.UpdateAllFromNamespace(ctx)
	assert.NoError(t, err)
	assert.Equal(t, count, 2)
	client.Options.Namespace = "two"
	count, err = client.UpdateAllFromNamespace(ctx)
	assert.NoError(t, err)
	assert.Equal(t, count, 0) // secrets already updated
}

func TestUpdateAll(t *testing.T) {
	ctx := context.TODO()
	first := createSecret("secret", "one", "right")
	second := createSecret("secret", "two", "right")
	third := createSecret("secret-2", "two", "right")
	fourth := createSecret("secret-2", "one", "right")
	fifth := createSecret("fake", "one", "left")
	faker := testclient.NewSimpleClientset(first, second, third, fourth, fifth)
	options := NewApplyOptions()
	options.AllNamespaces = true
	options.AllSecrets = true
	options.TargetOwner = "right"
	client := ApplyClient{
		Client:  faker,
		Options: options,
	}
	count, err := client.UpdateAll(ctx)
	assert.NoError(t, err)
	assert.Equal(t, count, 4)
	count, err = client.UpdateAll(ctx)
	assert.NoError(t, err)
	assert.Equal(t, count, 0) // secrets already updated
}

func TestRoot(t *testing.T) {
	ctx := context.TODO()
	first := createSecret("secret", "one", "right")
	second := createSecret("secret", "two", "right")
	third := createSecret("secret-2", "two", "right")
	fourth := createSecret("secret-2", "one", "right")
	fifth := createSecret("fake", "one", "left")
	sixth := createSecret("secret", "three", "right")
	seventh := createSecret("secret", "four", "right")
	eigth := createSecret("secret-2", "four", "right")
	nineth := createSecret("secret-2", "three", "right")
	tenth := createSecret("fake", "three", "left")
	faker := testclient.NewSimpleClientset(first, second, third, fourth, fifth, sixth, seventh, eigth, nineth, tenth)
	options := NewApplyOptions()
	options.AllNamespaces = true
	options.AllSecrets = true
	client := ApplyClient{
		Client:  faker,
		Options: options,
	}
	targets := []string{"secret"}
	err := Root(ctx, &client, targets)
	assert.NoError(t, err)
	client.Options.AllNamespaces = false
	err = Root(ctx, &client, targets)
	assert.NoError(t, err)
	client.Options.AllSecrets = false
	err = Root(ctx, &client, targets)
	assert.NoError(t, err)
	client.Options.AllNamespaces = true
	err = Root(ctx, &client, targets)
	assert.NoError(t, err)
}
