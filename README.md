# Security Challenges in Container Orchestration
### Kubernetes Vulnerabilities, Network Policies, and Threat Mitigation Strategies

![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.31.0-326CE5?logo=kubernetes&logoColor=white)
![Calico](https://img.shields.io/badge/CNI-Calico_v3.27-FB8C00?logo=linux&logoColor=white)
![Cilium](https://img.shields.io/badge/CNI-Cilium_v1.15-F8C517?logo=linux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_for_Containers-red)
![Platform](https://img.shields.io/badge/Platform-Ubuntu_24.04-E95420?logo=ubuntu&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**Author:** Sagarkumar Bhaveshbhai Bhikadiya | **Student ID:** 24051080 | **Module:** CT7P01 MSc Project

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Structure](#2-repository-structure)
3. [System Requirements](#3-system-requirements)
4. [Step 1 — Install Required Tools](#4-step-1--install-required-tools)
5. [Step 2 — Fix Kernel inotify Limits](#5-step-2--fix-kernel-inotify-limits)
6. [Step 3 — Create KIND Cluster Configuration](#6-step-3--create-kind-cluster-configuration)
7. [Step 4 — Build the Calico Cluster](#7-step-4--build-the-calico-cluster)
8. [Step 5 — Build the Cilium Cluster](#8-step-5--build-the-cilium-cluster)
9. [Step 6 — Verify Both Clusters Are Identical](#9-step-6--verify-both-clusters-are-identical)
10. [Step 7 — Deploy Google Microservices Demo](#10-step-7--deploy-google-microservices-demo)
11. [Step 8 — Access the Application](#11-step-8--access-the-application)
12. [Step 9 — Prepare the Attack Environment](#12-step-9--prepare-the-attack-environment)
13. [Step 10 — Phase 1: Baseline Attack Testing](#13-step-10--phase-1-baseline-attack-testing)
14. [Step 11 — Phase 2: Policy Enforcement Testing](#14-step-11--phase-2-policy-enforcement-testing)
15. [Step 12 — Phase 3: CNI Bypass Testing](#15-step-12--phase-3-cni-bypass-testing)
16. [Step 13 — Extended Bypass Test Suite](#16-step-13--extended-bypass-test-suite)
17. [Step 14 — B01 hostNetwork Manual Test](#17-step-14--b01-hostnetwork-manual-test)
18. [Step 15 — Remove Policies and Restore Clusters](#18-step-15--remove-policies-and-restore-clusters)
19. [Step 16 — Cluster Persistence and Safe Shutdown](#19-step-16--cluster-persistence-and-safe-shutdown)
20. [Known Errors and Fixes](#20-known-errors-and-fixes)

---

## 1. Project Overview

This repository is the complete reproducible research environment for an empirical comparison of two Kubernetes Container Network Interface (CNI) plugins under structured attack conditions mapped to the MITRE ATT&CK for Containers framework.

**What is being compared:**

| CNI | Enforcement Mechanism | Observability Tool |
|-----|-----------------------|--------------------|
| Calico | Linux `iptables` — writes packet filter rules into host netfilter chains | Calico flow logs |
| Cilium | `eBPF` — attaches programs directly to kernel network interfaces | Hubble — identity-aware real-time flow visibility |

**What is being measured:**

- Security enforcement effectiveness against 25 MITRE ATT&CK for Containers techniques across three phases
- CNI enforcement gaps across 24 bypass techniques in 6 categories
- Which attack techniques fall outside CNI enforcement scope entirely

**Target workload:** Google Microservices Demo (Online Boutique) — 11 polyglot microservices communicating over gRPC and HTTP, providing realistic east-west pod-to-pod traffic across multiple service boundaries.

**Test methodology:**

```
Phase 1 ── Zero NetworkPolicies — 25 techniques run at baseline
           Expected: all network attacks ALLOWED

Phase 2 ── Default-deny applied — same 25 techniques re-run
           Expected: network attacks BLOCKED

Phase 3 ── 4 bypass techniques against active default-deny
           Tests: enforcement gaps specific to each CNI architecture

Bypass  ── 24 extended bypass techniques across 6 categories
           Tests: architectural enforcement limits of each CNI
```

---

## 2. Repository Structure

```
.
├── README.md                          ← This file
├── LICENSE                            ← MIT licence
├── .gitignore                         ← Excludes logs and temp files
├── DISCLAIMER.md                      ← Security research disclaimer
│
├── clusters/
│   └── kind-config.yaml              ← Shared KIND cluster config (both clusters)
│
├── policies/
│   └── default-deny.yaml             ← Kubernetes default-deny NetworkPolicy
│
├── scripts/
│   ├── attack-test-suite.sh          ← 25-technique MITRE ATT&CK test suite
│   └── bypass-test-suite.sh          ← 24-technique CNI bypass test suite
│
├── app/
│   └── microservices-demo/           ← Google Microservices Demo
│       └── release/
│           └── kubernetes-manifests.yaml
│
├── results/                          ← Attack suite output (auto-generated)
│   ├── phase1/
│   ├── phase2/
│   └── phase3/
│
└── bypass-results/                   ← Bypass suite output (auto-generated)
```

---

## 3. System Requirements

| Requirement | Minimum | Tested Configuration |
|-------------|---------|---------------------|
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| RAM | 16 GB | 32 GB |
| CPU | 8 cores | 12 cores |
| Disk free | 40 GB | 60 GB |
| Linux kernel | 5.15+ | 6.17.0-14-generic |
| Internet | Required | — |

> Both clusters run simultaneously. Each uses approximately 6–8 GB RAM. Running on less than 16 GB will cause pods to be evicted.

---

## 4. Step 1 — Install Required Tools

Run each block in order. Do not skip any step.

### 1.1 Docker

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

sudo usermod -aG docker $USER
newgrp docker

sudo systemctl enable docker
sudo systemctl start docker

docker --version
docker info | grep "Server Version"
```

### 1.2 kubectl v1.31.0

```bash
curl -LO "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl
kubectl version --client
```

> Use v1.31.0 exactly — this matches the cluster node image. Version mismatch causes API incompatibilities.

### 1.3 KIND v0.24.0

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
kind version
```

### 1.4 Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version --short
```

### 1.5 Cilium CLI

```bash
CILIUM_CLI_VERSION=$(curl -s \
  https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)

curl -L --remote-name-all \
  https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz

sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
cilium version --client
```

### 1.6 Verify all five tools

```bash
echo "=== Tool Verification ===" && \
docker --version && \
kubectl version --client --short 2>/dev/null | head -1 && \
kind version && \
helm version --short && \
cilium version --client | head -1
```

All five must return version strings before continuing.

---

## 5. Step 2 — Fix Kernel inotify Limits

> **Mandatory.** Without this fix, running two KIND clusters simultaneously exhausts Linux kernel inotify limits and cluster creation fails with: `could not find a log line that matches Reached target Multi-User System`

```bash
sudo sysctl fs.inotify.max_user_instances=512
sudo sysctl fs.inotify.max_user_watches=524288

echo "fs.inotify.max_user_instances=512" | \
  sudo tee /etc/sysctl.d/99-kind.conf
echo "fs.inotify.max_user_watches=524288" | \
  sudo tee -a /etc/sysctl.d/99-kind.conf

sysctl fs.inotify.max_user_instances
sysctl fs.inotify.max_user_watches
```

Expected output:
```
fs.inotify.max_user_instances = 512
fs.inotify.max_user_watches = 524288
```

---

## 6. Step 3 — Create KIND Cluster Configuration

The file `clusters/kind-config.yaml` is shared by both clusters:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
nodes:
  - role: control-plane
  - role: worker
  - role: worker
```

**Why each setting matters:**

`disableDefaultCNI: true` — prevents KIND installing `kindnetd`. If kindnetd runs alongside Calico or Cilium, neither CNI takes exclusive control of packet forwarding and every test result is invalid.

`podSubnet: "10.244.0.0/16"` — explicit CIDR ensures both CNI plugins manage the same IP range. Without this, IPAM conflicts occur silently.

`2 worker nodes` — required for testing inter-node lateral movement and NetworkPolicy enforcement across node boundaries.

---

## 7. Step 4 — Build the Calico Cluster

### 4.1 Create the cluster

```bash
kind create cluster \
  --name calico-cluster \
  --config clusters/kind-config.yaml \
  --image kindest/node:v1.31.0
```

Nodes will show `NotReady` — correct. No CNI installed yet.

```bash
kubectl get nodes --context kind-calico-cluster
```

### 4.2 Install Calico via Tigera Operator

> **Order is mandatory.** Install the Tigera Operator FIRST — it registers the CRDs. Applying the Installation CR before the operator is ready produces: `no matches for kind "Installation" in version "operator.tigera.io/v1"`

```bash
# Step 1: Install Tigera Operator
kubectl apply --context kind-calico-cluster \
  -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/tigera-operator.yaml

# Wait for operator to be Available
kubectl wait deployment tigera-operator \
  -n tigera-operator \
  --context kind-calico-cluster \
  --for=condition=Available \
  --timeout=120s

# Step 2: Apply Installation CR
kubectl apply --context kind-calico-cluster \
  -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml
```

### 4.3 Wait for Calico pods

```bash
watch kubectl get pods -n calico-system --context kind-calico-cluster
```

Wait until all pods show `Running` — takes 3–5 minutes. Press `Ctrl+C` when done.

Expected:
```
calico-kube-controllers-xxx   1/1   Running
calico-node-xxx (x3)          1/1   Running
calico-typha-xxx              1/1   Running
csi-node-driver-xxx (x3)      2/2   Running
```

### 4.4 Verify nodes Ready

```bash
kubectl get nodes --context kind-calico-cluster
```

All three nodes must show `Ready`.

---

## 8. Step 5 — Build the Cilium Cluster

### 5.1 Create the cluster

```bash
kind create cluster \
  --name cilium-cluster \
  --config clusters/kind-config.yaml \
  --image kindest/node:v1.31.0
```

### 5.2 Install Cilium with Hubble

```bash
cilium install \
  --context kind-cilium-cluster \
  --version 1.15.0

cilium hubble enable \
  --context kind-cilium-cluster \
  --ui
```

### 5.3 Wait for Cilium pods

```bash
watch kubectl get pods -n kube-system --context kind-cilium-cluster | \
  grep -E "cilium|hubble"
```

Wait until all pods show `Running` — takes 3–5 minutes. Press `Ctrl+C` when done.

Expected:
```
cilium-xxx (x3)          1/1   Running
cilium-envoy-xxx (x3)    1/1   Running
cilium-operator-xxx (x2) 1/1   Running
hubble-relay-xxx         1/1   Running
hubble-ui-xxx            2/2   Running
```

### 5.4 Verify nodes Ready

```bash
kubectl get nodes --context kind-cilium-cluster
```

---

## 9. Step 6 — Verify Both Clusters Are Identical

Every check must pass before continuing. These confirm the controlled experiment is valid.

### 6.1 Kubernetes version parity

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  echo "=== $CTX ==="
  kubectl get nodes --context $CTX \
    -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}'
  echo ""
done
```

Both must print `v1.31.0`.

### 6.2 Confirm kindnetd is absent

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  echo "=== $CTX ==="
  kubectl get pods -n kube-system --context $CTX | grep kindnet
  echo "(blank above = kindnetd absent = CORRECT)"
done
```

Any `kindnet` pod means cluster was built without `disableDefaultCNI: true`. Delete and recreate it.

### 6.3 Full side-by-side identity check

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  echo ""
  echo "Cluster : $CTX"
  printf "  Nodes    : " && \
    kubectl get nodes --context $CTX --no-headers | wc -l
  printf "  K8s      : " && \
    kubectl get nodes --context $CTX \
      -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}' && echo ""
  printf "  OS       : " && \
    kubectl get nodes --context $CTX \
      -o jsonpath='{.items[0].status.nodeInfo.osImage}' && echo ""
  printf "  Kernel   : " && \
    kubectl get nodes --context $CTX \
      -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}' && echo ""
  printf "  Runtime  : " && \
    kubectl get nodes --context $CTX \
      -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}' && echo ""
done
```

Every value must be identical except cluster name and CNI.

---

## 10. Step 7 — Deploy Google Microservices Demo

### 7.1 Deploy to both clusters

```bash
kubectl apply \
  -f app/microservices-demo/release/kubernetes-manifests.yaml \
  --context kind-calico-cluster

kubectl apply \
  -f app/microservices-demo/release/kubernetes-manifests.yaml \
  --context kind-cilium-cluster
```

### 7.2 Wait for all pods

```bash
watch -n 5 "
echo '=== CALICO ===' && \
kubectl get pods -n default --context kind-calico-cluster --no-headers && \
echo '' && \
echo '=== CILIUM ===' && \
kubectl get pods -n default --context kind-cilium-cluster --no-headers"
```

All 12 pods must show `1/1 Running` on both clusters. Takes 3–6 minutes.

Expected pods: `adservice`, `cartservice`, `checkoutservice`, `currencyservice`, `emailservice`, `frontend`, `loadgenerator`, `paymentservice`, `productcatalogservice`, `recommendationservice`, `redis-cart`, `shippingservice`

### 7.3 Baseline verification

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  echo ""
  echo "Cluster: $CTX"
  printf "  Pods Running    : " && \
    kubectl get pods -n default --context $CTX \
      --no-headers | grep -c "Running"
  printf "  Services        : " && \
    kubectl get svc -n default --context $CTX \
      --no-headers | wc -l
  printf "  NetworkPolicies : " && \
    kubectl get networkpolicies -n default --context $CTX \
      --no-headers 2>/dev/null | wc -l
done
```

Both must show: `Pods Running: 12`, `Services: 13`, `NetworkPolicies: 0`

---

## 11. Step 8 — Access the Application

Open two terminals simultaneously:

**Terminal 1 — Calico cluster (port 8081):**
```bash
kubectl port-forward svc/frontend-external 8081:80 \
  --context kind-calico-cluster
```

**Terminal 2 — Cilium cluster (port 8082):**
```bash
kubectl port-forward svc/frontend-external 8082:80 \
  --context kind-cilium-cluster
```

Open in browser:
- Calico: http://localhost:8081
- Cilium: http://localhost:8082

The `loadgenerator` pod runs continuously creating realistic shopping traffic. `EXTERNAL-IP` showing `<pending>` is expected — KIND has no cloud load balancer.

---

## 12. Step 9 — Prepare the Attack Environment

### 9.1 Make scripts executable

```bash
chmod +x scripts/attack-test-suite.sh scripts/bypass-test-suite.sh
mkdir -p results/phase1 results/phase2 results/phase3 bypass-results
```

### 9.2 Deploy the attacker pod

The attacker pod (`nicolaka/netshoot`) simulates a compromised application pod. It has `curl`, `nc`, `nmap`, `tcpdump`, `redis-cli`, `dig`, `iptables`, and `kubectl` available.

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  kubectl run attacker-netshoot \
    --image=nicolaka/netshoot \
    --restart=Never \
    --context $CTX \
    -n default \
    --overrides='{
      "spec": {
        "containers": [{
          "name": "attacker-netshoot",
          "image": "nicolaka/netshoot",
          "command": ["sleep", "86400"],
          "securityContext": {
            "capabilities": {
              "add": ["NET_ADMIN", "NET_RAW"]
            }
          }
        }]
      }
    }'
done

# Wait for both to be Ready
kubectl wait pod attacker-netshoot -n default \
  --context kind-calico-cluster \
  --for=condition=Ready --timeout=90s

kubectl wait pod attacker-netshoot -n default \
  --context kind-cilium-cluster \
  --for=condition=Ready --timeout=90s

# Verify
kubectl get pods -n default --context kind-calico-cluster | grep attacker
kubectl get pods -n default --context kind-cilium-cluster | grep attacker
```

Both must show `1/1 Running`.

---

## 13. Step 10 — Phase 1: Baseline Attack Testing

Phase 1 runs all 25 MITRE ATT&CK techniques with zero NetworkPolicies applied. Establishes the pre-policy attack surface.

```bash
./scripts/attack-test-suite.sh kind-calico-cluster phase1
./scripts/attack-test-suite.sh kind-cilium-cluster phase1
```

### Expected Phase 1 outcome

Both clusters must produce identical results. Any difference means the clusters are not equivalent.

| Test group | Expected | Reason |
|-----------|----------|--------|
| Network attacks (T1190, T1046, T1210, T1021.004, T1048, T1499) | ALLOWED | Kubernetes default-allow networking |
| API server attacks (T1613, T1552.007b, T1609, T1489, T1610, T1059.013) | BLOCKED | RBAC — independent of CNI |
| Filesystem attacks (T1552.007, T1552.004, T1611, T1040, T1049, T1083) | ALLOWED | No network connection required |

BLOCKED results for API server tests in Phase 1 are RBAC-enforced — not CNI. Document these separately.

### Output location

```
results/kind-calico-cluster-phase1-TIMESTAMP.txt   ← Human-readable report
results/kind-calico-cluster-phase1-TIMESTAMP.csv   ← ATT&CK Coverage Matrix CSV
results/kind-cilium-cluster-phase1-TIMESTAMP.txt
results/kind-cilium-cluster-phase1-TIMESTAMP.csv
```

---

## 14. Step 11 — Phase 2: Policy Enforcement Testing

Phase 2 applies a strict default-deny NetworkPolicy then re-runs all 25 techniques.

### 11.1 The default-deny policy

`policies/default-deny.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

`podSelector: {}` selects every pod in the namespace. Both `Ingress` and `Egress` are blocked with no allow exceptions — complete pod isolation.

> After applying, the application stops working. This is correct — the policy is enforcing. Do not add allow rules during Phase 2.

### 11.2 Pre-stage filesystem tests inside pods

The default-deny egress policy cuts the `kubectl exec` API server tunnel once applied. Stage filesystem tests inside pods BEFORE applying the policy.

```bash
# Stage on Calico pod
kubectl exec attacker-netshoot -n default --context kind-calico-cluster -- sh -c '
cat > /tmp/fs-tests.sh << "SCRIPT"
#!/bin/sh
echo "=== T1552.007 SA TOKEN ==="
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
if [ ${#TOKEN} -gt 20 ]; then echo "ALLOWED — token readable, ${#TOKEN} chars"
else echo "BLOCKED — token not readable"; fi
echo "=== T1552.004 ENV VARS ==="
COUNT=$(env | grep -cE "SERVICE_HOST|SERVICE_PORT|REDIS|PAYMENT|CHECKOUT" 2>/dev/null || echo 0)
if [ "$COUNT" -gt 0 ]; then echo "ALLOWED — ${COUNT} sensitive vars found"
else echo "BLOCKED"; fi
echo "=== T1040 TCPDUMP ==="
RESULT=$(timeout 5 tcpdump -i eth0 -c 3 -nn 2>&1 | tail -2)
echo "$RESULT" | grep -qiE "IP |captured|listening" && echo "ALLOWED — packets captured" || echo "BLOCKED — $RESULT"
echo "=== T1049 PROC NET TCP ==="
COUNT=$(cat /proc/net/tcp 2>/dev/null | wc -l)
[ "$COUNT" -gt 1 ] && echo "ALLOWED — ${COUNT} TCP entries" || echo "BLOCKED"
echo "=== T1083 SECRET FILES ==="
COUNT=$(find /var/run/secrets -type f 2>/dev/null | wc -l)
[ "$COUNT" -gt 0 ] && echo "ALLOWED — ${COUNT} files" || echo "BLOCKED"
echo "=== T1611 HOST FILESYSTEM ==="
RESULT=$(ls /proc/1/root/etc/ 2>/dev/null | head -3)
[ -n "$RESULT" ] && echo "ALLOWED — $RESULT" || echo "BLOCKED"
echo "=== T1562.001 IPTABLES ==="
RESULT=$(iptables -L INPUT 2>&1 | head -2)
echo "$RESULT" | grep -qiE "Chain|policy" && echo "ALLOWED — rules visible" || echo "BLOCKED"
echo "=== DONE ==="
SCRIPT
chmod +x /tmp/fs-tests.sh && echo "Staged on CALICO"
'

# Stage on Cilium pod
kubectl exec attacker-netshoot -n default --context kind-cilium-cluster -- sh -c '
cat > /tmp/fs-tests.sh << "SCRIPT"
#!/bin/sh
echo "=== T1552.007 SA TOKEN ==="
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
if [ ${#TOKEN} -gt 20 ]; then echo "ALLOWED — token readable, ${#TOKEN} chars"
else echo "BLOCKED — token not readable"; fi
echo "=== T1552.004 ENV VARS ==="
COUNT=$(env | grep -cE "SERVICE_HOST|SERVICE_PORT|REDIS|PAYMENT|CHECKOUT" 2>/dev/null || echo 0)
if [ "$COUNT" -gt 0 ]; then echo "ALLOWED — ${COUNT} sensitive vars found"
else echo "BLOCKED"; fi
echo "=== T1040 TCPDUMP ==="
RESULT=$(timeout 5 tcpdump -i eth0 -c 3 -nn 2>&1 | tail -2)
echo "$RESULT" | grep -qiE "IP |captured|listening" && echo "ALLOWED — packets captured" || echo "BLOCKED — $RESULT"
echo "=== T1049 PROC NET TCP ==="
COUNT=$(cat /proc/net/tcp 2>/dev/null | wc -l)
[ "$COUNT" -gt 1 ] && echo "ALLOWED — ${COUNT} TCP entries" || echo "BLOCKED"
echo "=== T1083 SECRET FILES ==="
COUNT=$(find /var/run/secrets -type f 2>/dev/null | wc -l)
[ "$COUNT" -gt 0 ] && echo "ALLOWED — ${COUNT} files" || echo "BLOCKED"
echo "=== T1611 HOST FILESYSTEM ==="
RESULT=$(ls /proc/1/root/etc/ 2>/dev/null | head -3)
[ -n "$RESULT" ] && echo "ALLOWED — $RESULT" || echo "BLOCKED"
echo "=== T1562.001 IPTABLES ==="
RESULT=$(iptables -L INPUT 2>&1 | head -2)
echo "$RESULT" | grep -qiE "Chain|policy" && echo "ALLOWED — rules visible" || echo "BLOCKED"
echo "=== DONE ==="
SCRIPT
chmod +x /tmp/fs-tests.sh && echo "Staged on CILIUM"
'
```

### 11.3 Apply policy then run tests immediately

```bash
# Apply policy to both clusters
kubectl apply -f policies/default-deny.yaml --context kind-calico-cluster
kubectl apply -f policies/default-deny.yaml --context kind-cilium-cluster

# Run pre-staged filesystem tests IMMEDIATELY after applying policy
echo "=== CALICO FILESYSTEM TESTS ===" && \
kubectl exec attacker-netshoot -n default --context kind-calico-cluster \
  -- /tmp/fs-tests.sh

echo "=== CILIUM FILESYSTEM TESTS ===" && \
kubectl exec attacker-netshoot -n default --context kind-cilium-cluster \
  -- /tmp/fs-tests.sh

# Run Phase 2 network tests
./scripts/attack-test-suite.sh kind-calico-cluster phase2
./scripts/attack-test-suite.sh kind-cilium-cluster phase2
```

### 11.4 Expected Phase 2 outcome

All 18 network-layer attack techniques return BLOCKED on both clusters. Seven filesystem and capability-based tests (T1552.007, T1552.004, T1611, T1040, T1083, T1557.002, T1562.001) remain ALLOWED — they operate below the L3/L4 CNI enforcement boundary and cannot be mitigated by NetworkPolicy.

---

## 15. Step 12 — Phase 3: CNI Bypass Testing

Phase 3 runs 4 bypass techniques against the active default-deny policy.

```bash
# Verify policy is still applied
kubectl get networkpolicies -n default --context kind-calico-cluster
kubectl get networkpolicies -n default --context kind-cilium-cluster

./scripts/attack-test-suite.sh kind-calico-cluster phase3
./scripts/attack-test-suite.sh kind-cilium-cluster phase3
```

### Phase 3 techniques

| ID | Technique | What is tested |
|----|-----------|----------------|
| B1 | T1599 — IPv6 Gap | Whether default-deny covers IPv6 as well as IPv4 |
| B2 | T1571 — Non-Standard Port | Whether default-deny covers all ports or only declared ones |
| B3 | T1611 — hostNetwork Pod | Whether CNI enforces beyond pod network namespace |
| B4 | T1046 — DNS Post-Deny | Whether DNS egress survives a strict default-deny |

> B1 returns ERROR if IPv6 is not enabled in KIND config — expected with this configuration.

> B3 produces different results between Calico and Cilium. See Step 14 for the corrected manual test that produces accurate results.

---

## 16. Step 13 — Extended Bypass Test Suite

24 bypass techniques across 6 categories tested against the active default-deny policy.

```bash
kubectl apply -f policies/default-deny.yaml --context kind-calico-cluster
kubectl apply -f policies/default-deny.yaml --context kind-cilium-cluster

./scripts/bypass-test-suite.sh kind-calico-cluster
./scripts/bypass-test-suite.sh kind-cilium-cluster
```

### Bypass categories

| Category | Tests | What is tested |
|----------|-------|----------------|
| Cat 1 — Network Namespace | B01–B04 | hostNetwork, hostPID, hostIPC, privileged containers |
| Cat 2 — Protocol and Port | B05–B09 | IPv6, UDP, SCTP, high port ranges, ICMP |
| Cat 3 — Service and Routing | B10–B13 | NodePort, direct pod IP, DNS enumeration, link-local |
| Cat 4 — Kernel and Capability | B14–B17 | Raw sockets, iptables manipulation, /proc pivot, loopback |
| Cat 5 — CNI-Specific | B18–B20 | Race condition, cross-namespace, headless service |
| Cat 6 — Application Layer | B21–B24 | HTTP CONNECT, DNS tunneling, WebSocket upgrade, gRPC reflection |

Results saved to `bypass-results/`.

> **Note on B15 (iptables flush):** Both clusters record the same result but the security meaning differs. On Calico, flushing the iptables FORWARD chain removes Calico's actual enforcement rules — policy is unenforced until calico-node rewrites them. On Cilium, the same flush has zero effect — Cilium's enforcement lives in eBPF maps attached to veth interfaces, completely separate from netfilter.

> **Note on Category 1 (B01–B04):** The automated script has a status parsing bug that causes running pods to be classified as errors. Use the manual test in Step 14 for accurate B01 results.

---

## 17. Step 14 — B01 hostNetwork Manual Test

This manual test produces the correct B01 result. It bypasses DNS to avoid false BLOCKED results caused by default-deny blocking UDP 53.

### 14.1 Get redis-cart ClusterIPs

```bash
echo "CALICO redis-cart IP:" && \
kubectl get svc redis-cart -n default --context kind-calico-cluster \
  -o jsonpath='{.spec.clusterIP}' && echo ""

echo "CILIUM redis-cart IP:" && \
kubectl get svc redis-cart -n default --context kind-cilium-cluster \
  -o jsonpath='{.spec.clusterIP}' && echo ""
```

Note both IPs before continuing.

### 14.2 Ensure default-deny is applied

```bash
kubectl apply -f policies/default-deny.yaml --context kind-calico-cluster
kubectl apply -f policies/default-deny.yaml --context kind-cilium-cluster
```

### 14.3 Deploy hostNetwork pods

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  kubectl run bypass-hostnet \
    --image=nicolaka/netshoot \
    --restart=Never -n default \
    --context $CTX \
    --overrides='{"spec":{"hostNetwork":true,"containers":[{"name":"bypass-hostnet","image":"nicolaka/netshoot","command":["sleep","120"]}]}}'
done

sleep 25
```

### 14.4 Test using direct ClusterIP — no DNS

Replace `<CALICO_REDIS_IP>` and `<CILIUM_REDIS_IP>` with the IPs from Step 14.1:

```bash
echo "=== CALICO hostNetwork bypass ===" && \
kubectl exec bypass-hostnet -n default --context kind-calico-cluster \
  -- sh -c "nc -z -w3 <CALICO_REDIS_IP> 6379 && echo BYPASS_CONFIRMED || echo BLOCKED"

echo "=== CILIUM hostNetwork bypass ===" && \
kubectl exec bypass-hostnet -n default --context kind-cilium-cluster \
  -- sh -c "nc -z -w3 <CILIUM_REDIS_IP> 6379 && echo BYPASS_CONFIRMED || echo BLOCKED"
```

> Using the hostname instead of the direct IP will always return a false BLOCKED because DNS is cut by default-deny. Always use the ClusterIP directly for this test.

### 14.5 Cleanup

```bash
for CTX in kind-calico-cluster kind-cilium-cluster; do
  kubectl delete pod bypass-hostnet -n default \
    --context $CTX --ignore-not-found=true
done
```

---

## 18. Step 15 — Remove Policies and Restore Clusters

After all testing is complete:

```bash
kubectl delete networkpolicy default-deny-all \
  -n default --context kind-calico-cluster
kubectl delete networkpolicy default-deny-all \
  -n default --context kind-cilium-cluster

# Verify removed
kubectl get networkpolicies -n default --context kind-calico-cluster
kubectl get networkpolicies -n default --context kind-cilium-cluster
# Both output: No resources found
```

Wait 60 seconds then verify application recovery:

```bash
kubectl get pods -n default --context kind-calico-cluster
kubectl get pods -n default --context kind-cilium-cluster
```

All 12 pods return to `Running` automatically — no redeployment needed.

---

## 19. Step 16 — Cluster Persistence and Safe Shutdown

> KIND clusters run as Docker containers. When Docker stops at OS shutdown, cluster state is lost. Always stop cluster containers cleanly before shutting down.

### Safe shutdown — run before every PC shutdown

```bash
docker stop \
  calico-cluster-control-plane \
  calico-cluster-worker \
  calico-cluster-worker2 \
  cilium-cluster-control-plane \
  cilium-cluster-worker \
  cilium-cluster-worker2
```

### Start clusters after boot

```bash
sudo systemctl start docker

docker start \
  calico-cluster-control-plane \
  calico-cluster-worker \
  calico-cluster-worker2 \
  cilium-cluster-control-plane \
  cilium-cluster-worker \
  cilium-cluster-worker2

sleep 90

kubectl get nodes --context kind-calico-cluster
kubectl get nodes --context kind-cilium-cluster
kubectl get pods -n default --context kind-calico-cluster
kubectl get pods -n default --context kind-cilium-cluster
```

All nodes and pods recover automatically.

### Full rebuild if clusters are lost

If `kind get clusters` returns nothing, rebuild from Step 4. Takes approximately 30 minutes.

---

## 20. Known Errors and Fixes

### inotify limit error

```
could not find a log line that matches "Reached target Multi-User System"
```
**Fix:** Run Step 2 — mandatory for dual-cluster setup.

---

### Calico CRD not found

```
no matches for kind "Installation" in version "operator.tigera.io/v1"
```
**Fix:** Operator not ready before CR was applied.
```bash
kubectl wait deployment tigera-operator -n tigera-operator \
  --context kind-calico-cluster \
  --for=condition=Available --timeout=120s

kubectl apply --context kind-calico-cluster \
  -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml
```

---

### Port already in use

```
error: address already in use
```
**Fix:**
```bash
ss -tlnp | grep 8081
kill <PID>
kubectl port-forward svc/frontend-external 8081:80 --context kind-calico-cluster
```

---

### Attacker pod in Unknown state

```
attacker-netshoot   0/1   Unknown
```
**Fix:**
```bash
kubectl delete pod attacker-netshoot -n default \
  --context kind-calico-cluster --force --grace-period=0
kubectl delete pod attacker-netshoot -n default \
  --context kind-cilium-cluster --force --grace-period=0
```
The attack-test-suite.sh script recreates the pod automatically on the next run.

---

### B01 hostNetwork shows Name does not resolve

```
nc: getaddrinfo for host "redis-cart.default.svc.cluster.local": Name does not resolve
```
**Fix:** Default-deny blocks DNS. Use the direct ClusterIP — see Step 14.

---

### kubectl exec fails during Phase 2

Default-deny blocks the API server exec websocket tunnel into pods. This is expected — the policy is working. Network-layer tests are unaffected since a failed TCP connection correctly returns BLOCKED. Pre-stage filesystem tests before applying the policy — see Step 11.2.

---

### kind get clusters returns nothing

```
No kind clusters found.
```
**Fix:** Clusters destroyed at shutdown. Run the safe shutdown procedure in Step 16 before every shutdown. Rebuild from Step 4 to recover.

---

## Acknowledgements

- [Google Cloud Platform — Microservices Demo](https://github.com/GoogleCloudPlatform/microservices-demo)
- [Tigera — Calico CNI](https://github.com/projectcalico/calico)
- [Cilium Authors — Cilium + Hubble](https://github.com/cilium/cilium)
- [MITRE Corporation — ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [KIND — Kubernetes IN Docker](https://github.com/kubernetes-sigs/kind)

---

## Citation

```
Bhikadiya, S.B. (2026). Security Challenges in Container Orchestration:
Kubernetes Vulnerabilities, Network Policies, and Threat Mitigation Strategies.
MSc Dissertation, CT7P01. Student ID: 24051080.
```
