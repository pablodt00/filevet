# filevet Helm chart

Runs the filevet REST API, queue workers, Redis and optionally ClamAV, with restricted pod security and NetworkPolicies that block worker egress.

```sh
helm install filevet oci://ghcr.io/pablodt00/charts/filevet --version <version> \
  --namespace filevet --create-namespace \
  --set apiKeys="$(printf %s "$MY_KEY" | sha256sum | cut -d' ' -f1)"
```

Quickstart, values and the isolation model are in [docs/kubernetes.md](../../docs/kubernetes.md). Every value and its default is in [values.yaml](values.yaml).
