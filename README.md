# KES to ESO
kes-to-eso is a tool driven to facilitate migrating from [kubernetes-external-secrets](https://github.com/external-secrets/kubernetes-external-secrets) to [external-secrets](https://github-com/external-secrets/external-secrets)

It has a binary tool which makes the translation between `kes-ExternalSecrets` and `eso-ExternalSecrets+SecretStores`. By default, it creates `ClusterSecretStores` bound to any credentials already available for `kes`. Whenever a credential is stored only in environment variables, it will also output the appropriate secret to be created.

# Usage

The migration process can be done in two ways: manually, or automatically.

## Automatic Migration

Automatic Migration is useful for any user that don't have any templated kes-files.

```
vi migrate.sh # EDIT KES NAMESPACE AND ESO NAMESPACE ENV VARS
./migrate.sh
```

This script will run the following steps:
 * Download KES ExternalSecrets files from cluster and save them in `kes_files` folder
 * Scale ESO replicaset to 0
 * Run `kestoeso generate` to generate ESO ExternalSecrets+SecretStores in `eso_files` folder
 * Apply ESO ExternalSecrets+SecretStores in cluster
 * Scale KES replicaset to 0
 * run `kestoeso apply` on all namespaces to remove kes ownership from all kes-managed Secrets
*  Scale ESO replicaset to 1

Rollback steps can be achieved by simply scaling KES replicaset to 1 and ESO replicaset to 0. This is also available at

```
./rollback.sh
```

## Manual Migration

If you are unsure about the migration script, want to migrate only a given subset of ExternalSecrets or have custom templated kes files in your setup, a manual migration is recommended for you. In order to do so, here are the steps needed.

1) Have available / download KES external-secrets that you want to migrate. You can achieve that by running `bash -c "$(kubectl get externalsecrets.kubernetes-client.io -n <MY_NAMESPACE> -o=jsonpath='{range .items[*]}{"kubectl get externalsecrets.kubernetes-client.io -o yaml -n "}{.metadata.namespace}{" "}{.metadata.name}{" >> path/to/input/"}{.metadata.namespace}{"-"}{.metadata.name}{".yaml; "}{end}')"` for a full namespace download.
2) Generate ESO files by typing `kestoeso generate -i path/to/input -o path/to/output -n <namespace where kes is deployed>`
3) Review generated files. `kestoeso` will output any warnings whenever a given kes input could not be properly translated. It will already template the file for you, so all you need to do is open that file and properly edit it.
4) Include any templated files: `kestoeso` will abort whenever it finds a `template` usage or a `path` usage in kes ExternalSecrets, skipping that file completly.
5) Create and update any ServiceAccount / Secret references that you think it might be needed. Update ClusterSecretStores to SecretStores, if desired
6) Apply generated ESO files to your deployment
7) Because ownership is still set to KES, and any KES ExternalSecret deletion would cause secret deletion, it is recommended to update the secret ownership to ESO. In order to do so, KES deployment must be off, otherwise it will steal ownership from ESO. After scaling KES to 0, you can manually edit each secret ownership, or use `kestoeso apply`. It is possible to select a given namespace and a given secret arrays to be changed, or a combination of both. `kestoeso apply` will manually remove any ownership from `kes` to let that secret be available to both `kes` and `eso`. IF eso is already available, secret ownership will be passed to `eso`. This can be checked with `kubectl get secrets <secretname> -o yaml | grep -i ownerReferences -A10`


## Warnings
* This migration process still uses secrets and service accounts created by and used by `kes`. Do not delete them before being sure that any provider authorization is already updated with a new serviceAccount for `eso`
* If `kestoeso` outputs any warnings, do not apply externalSecrets to kubernetes! Although the apply will work correctly, that does not indicate a healthy behavior of the migration process!
## Limitations
* Not possible to migrate templated ExternalSecrets definitions
* Not possible to migrate ExternalSecrets that uses `path` in both `Data` or `DataFrom` definitions
* Not posible to automatically generate appropriate `SecretStores` (although you can ask `kestoeso` to do so, you still need to create every secret and serviceAccount on the appropriate namespace where the `SecretStore` is created, besides reviewing any permissions on every provider).
