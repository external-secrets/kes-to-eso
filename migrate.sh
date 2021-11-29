#! /bin/bash -e
KES_NAMESPACE="kes"
ESO_NAMESPACE="es"
# Have KES and ESO both installed
#Step 0  manual step to get .yaml files for KES External Secrets
## can be done with:
mkdir -p kes_files
mkdir -p eso_files
bash -c "$(kubectl get externalsecrets.kubernetes-client.io -A -o=jsonpath='{range .items[*]}{"kubectl get externalsecrets.kubernetes-client.io -o yaml -n "}{.metadata.namespace}{" "}{.metadata.name}{" >> kes_files/"}{.metadata.namespace}{"-"}{.metadata.name}{".yaml; "}{end}')"

#Step 1 Scale ESO to 0 (safeguard, really)
kubectl scale deployment -n $ESO_NAMESPACE external-secrets --replicas=0

#Step 2 Generate ESO files and apply them
bin/kestoeso generate -i kes_files -o eso_files -n $KES_NAMESPACE

kubectl apply -f eso_files

# Step 3 - Scale KES to 0
kubectl scale deployment -n $KES_NAMESPACE kubernetes-external-secrets --replicas=0

# Step 4 - Update Ownership references
bin/kestoeso apply --all-secrets --all-namespaces #
# kestoeso apply -n changeme-my-target-ns -s my-secret-1,my-secret-2 # Alternative for people that want to do a step-by-step migration

# Step 5 - Scale ESO to 1
kubectl scale deployment -n $ESO_NAMESPACE external-secrets --replicas=1
