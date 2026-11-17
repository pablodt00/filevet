# Kubernetes

The Helm chart in [`charts/filevet`](../charts/filevet) runs the REST API, the queue workers, Redis and, optionally, ClamAV. Each release publishes it to GHCR as an OCI artifact:

```sh
helm install filevet oci://ghcr.io/pablodt00/charts/filevet --version <version> \
  --namespace filevet --create-namespace \
  --set apiKeys="$(printf %s "$MY_KEY" | sha256sum | cut -d' ' -f1)"
```

## What gets deployed

| Component | Kind | Notes |
| --- | --- | --- |
| API | Deployment and Service | `filevet serve` on port 8000. Liveness on `/healthz`, readiness on `/readyz`, which also checks Redis and clamd |
| Worker | Deployment | `filevet worker`. Optionally scaled by KEDA on the length of the `filevet:queue` list |
| Redis | Deployment and Service | `redis:8-alpine` with no persistence, like the Compose file. Turn it off and set `redis.externalUrl` to use your own |
| ClamAV | Deployment and Service | Off by default. `clamd` on TCP 3310 with a `freshclam` sidecar on a shared signature volume, seeded from the signatures in the image |
| Secret | Secret | `FILEVET_API_KEYS`, `FILEVET_SPOOL_KEY` and the optional `FILEVET_WEBHOOK_SECRET` |
| NetworkPolicy | NetworkPolicy | One per component, see below |
| ServiceMonitor | ServiceMonitor | Off by default. Scrapes `/metrics` on the API for the Prometheus Operator |

## Local quickstart with kind

```sh
kind create cluster --name filevet
docker build -t filevet:test .
kind load docker-image filevet:test --name filevet

kubectl create namespace filevet
kubectl label namespace filevet pod-security.kubernetes.io/enforce=restricted

export MY_KEY=change-me
helm install fv charts/filevet -n filevet \
  --set image.repository=filevet --set image.tag=test --set image.pullPolicy=Never \
  --set apiKeys="$(printf %s "$MY_KEY" | sha256sum | cut -d' ' -f1)" \
  --set clamav.enabled=true --wait --timeout 10m

kubectl -n filevet port-forward svc/fv-filevet-api 8000:8000 &
mkdir -p tmp-samples && printf '%%PDF-1.4\n%%%%EOF\n' > tmp-samples/benign.pdf
curl -H "Authorization: Bearer $MY_KEY" --data-binary @tmp-samples/benign.pdf \
  "http://localhost:8000/v1/scans?name=benign.pdf"
```

kind's default CNI enforces NetworkPolicy, so the egress rules below are active on a local cluster too. With k3d, the built-in network policy controller does the same: `k3d cluster create filevet`, then `k3d image import filevet:test -c filevet` in place of `kind load`.

Remove everything with `kind delete cluster --name filevet`.

## Values

The full list with defaults is in [`values.yaml`](../charts/filevet/values.yaml). The ones you will most likely change:

| Value | Default | Effect |
| --- | --- | --- |
| `apiKeys` | | Comma-separated SHA-256 hashes of the API keys. Required unless `existingSecret` is set |
| `spoolKey` | generated | Fernet key for queued uploads. Generated on install and kept across upgrades |
| `existingSecret` | | Use your own Secret with the keys `FILEVET_API_KEYS`, `FILEVET_SPOOL_KEY` and optionally `FILEVET_WEBHOOK_SECRET` |
| `policy` | `default` | Built-in policy name or a policy file path (`FILEVET_POLICY`) |
| `extraEnv` | `[]` | More environment variables for the API and the worker, such as `FILEVET_SYNC_MAX_BYTES` or `FILEVET_RATE_LIMIT` (see [api.md](api.md)) |
| `api.replicas`, `worker.replicas` | `2` | Replica counts. `worker.replicas` is ignored when KEDA is on |
| `api.sandbox`, `worker.sandbox` | `subprocess` | Sandbox backend (`FILEVET_SANDBOX`) |
| `api.runtimeClassName`, `worker.runtimeClassName` | | RuntimeClass for the pods, for example `gvisor` |
| `worker.keda.enabled` | `false` | Create a KEDA `ScaledObject` that scales workers on queue length. Needs KEDA installed |
| `redis.enabled`, `redis.externalUrl` | `true`, | In-chart Redis or an external URL |
| `clamav.enabled` | `false` | Deploy ClamAV and point `FILEVET_CLAMD` at it |
| `webhook.secret`, `webhook.hosts` | | Signed webhooks. Each host also needs an egress rule in `networkPolicy.extraEgress` |
| `networkPolicy.apiFrom` | `[]` | NetworkPolicy peers allowed to reach the API. Empty allows any source |
| `networkPolicy.extraEgress` | `[]` | Extra egress rules for the API and workers, for an external Redis or webhook hosts |
| `serviceMonitor.enabled` | `false` | Create a ServiceMonitor for `/metrics` |
| `tmpSizeLimit` | `1Gi` | Size of the in-memory `/tmp` where scans keep their temp copies. It counts against the pod's memory limit |

The KEDA trigger reads the Redis address without credentials. If your external Redis needs a password, add a KEDA `TriggerAuthentication` yourself.

## Isolation

The API scans small uploads in the request, and workers scan the queued ones, so both handle hostile files. The chart treats them the same way.

### Pod Security

Every pod meets the `restricted` [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/): it runs as a non-root user (10001 for filevet), drops all capabilities, can't escalate privileges, uses the runtime's default seccomp profile and has a read-only root filesystem. The only writable path is an in-memory `emptyDir` at `/tmp` with a size limit. Service account tokens aren't mounted. Label the namespace so the API server rejects anything weaker:

```sh
kubectl label namespace filevet pod-security.kubernetes.io/enforce=restricted
```

### NetworkPolicy

Workers accept no inbound traffic, and the API only accepts traffic on port 8000. Their egress is limited to DNS, the in-chart Redis and clamd. Anything else, the internet and the Kubernetes API included, is dropped unless you add it to `networkPolicy.extraEgress`. Redis accepts connections only from the API and workers and has no egress. ClamAV accepts connections from the API and workers on 3310, and can reach DNS and port 443 for signature updates (`networkPolicy.clamavEgress`). NetworkPolicy only works if your CNI enforces it. Most do (Calico, Cilium, kindnet, k3s), but check yours.

### RuntimeClass

Setting `worker.runtimeClassName: gvisor` (and `api.runtimeClassName`, if the API scans in the request) runs those pods under gVisor's user-space kernel, so a parser exploit reaches gVisor instead of the host kernel. The cluster needs gVisor installed on its nodes and a RuntimeClass:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

Inside a gVisor pod, keep the `subprocess` sandbox backend. gVisor is the outer boundary, and each analyzer still gets its own process with a timeout and a memory limit. The backends and what each one guarantees are in [security-model.md](security-model.md).

## Resources

Every container has requests and limits. A worker runs one analyzer process at a time, capped at 1 GB of address space by default, plus the in-memory `/tmp`, so the worker's default limit is 3 GiB. ClamAV needs about 2 GiB to load its signatures. Adjust the numbers once you've measured your own file mix.
