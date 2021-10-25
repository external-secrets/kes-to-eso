KES_NAMESPACE="kes"
ESO_NAMESPACE="es"

kubectl scale deployment -n $ESO_NAMESPACE external-secrets --replicas=0
kubectl scale deployment -n $KES_NAMESPACE kubernetes-external-secrets --replicas=1


## Check manually that secrets are now with owner Referenced to kubernetes-client
## then kubectl delete -f eso_files
