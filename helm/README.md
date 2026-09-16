# Helm Deployment

## Prerequisites

### Kubernetes cluster

A local [Rancher Desktop](https://rancherdesktop.io/) (K3s) cluster.

### Secrets

Create the required secrets before deploying:

```bash
kubectl --context=rancher-desktop delete secret postgres-secret
kubectl --context=rancher-desktop create secret generic postgres-secret \
  --from-literal=POSTGRES_USER=postgres \
  --from-literal=POSTGRES_PASSWORD=<password>

kubectl --context=rancher-desktop delete secret keycloak-secret
kubectl --context=rancher-desktop create secret generic keycloak-secret \
  --from-literal=ADMIN_USERNAME=admin \
  --from-literal=ADMIN_PASSWORD=<password>
```

## Deploy

```bash
helm upgrade --kube-context=rancher-desktop --install nessus-services ./helm -f ./helm/values-services-dev.yaml
```

## Services

| Service    | In-cluster           | NodePort              |
|------------|----------------------|-----------------------|
| PostgreSQL | `postgres:5432`      | `localhost:30543`     |
| Keycloak   | `keycloak:8080`      | `localhost:30800`     |

Keycloak admin console: http://localhost:30800

## Teardown

```bash
helm --kube-context=rancher-desktop uninstall nessus-services
```

The PostgreSQL PVC is retained (`helm.sh/resource-policy: keep`). To remove it:

```bash
kubectl --context=rancher-desktop delete pvc postgres-pvc
```
