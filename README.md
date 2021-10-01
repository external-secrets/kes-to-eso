# KES to ESO
kes-to-eso is a tool driven to facilitate migrating from [kubernetes-external-secrets](https://github.com/external-secrets/kubernetes-external-secrets) to [external-secrets](https://github-com/external-secrets/external-secrets)

It's currently in a design phase on how to provide the highest value for end users.

This project is currently WIP, no functionalities so far.

## Main Goals
* From KES yamls, generate ESO ExternalSecrets
* From KES deployment file, generate ESO SecretStores / ClusterSecretStores
* From command line and KES yamls, generate ESO SecretStores / ClusterSecretStores
* From kube-api make a blue-green migration.

Although these are the main goals, an MVP approach of migrating YAMLs only might suffice our objectives, provided that the initial migration generates working ESO YAML files.

## Roadmap
### 0.1.0
* KES + KES Deployment YAML is converted to ESO YAMLs

### 0.2.0
* KES + Command line is converted to ESO YAMLs

### 0.3.0
* KubeAPI integration for obtaining KES + KES Deployment
* KubeAPI integration for installing ESO YAMLs

### 0.4.0
* Handle Blue/Green Deployment
* Validate new ESO behavior
