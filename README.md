# K8s-CNI-policies

**Dissertation Research Repository**  
*Empirical Comparison of Calico and Cilium CNI Plugins in Kubernetes: Enforcement Resilience, Observability, and Architectural Divergence*

**Author:** Sagarkumar B Bhikadiya  
**Student ID:** 24051080  
**Module:** CT7P01 — MSc Computer Networks and Cyber Security  
**Institution:** London Metropolitan University  
**Supervisor:** Astrit Krasniqi  

<div align="center">

![GitHub repo size](https://img.shields.io/github/repo-size/SB-Bhikadiya/K8s-CNI-policies?style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/SB-Bhikadiya/K8s-CNI-policies?style=flat-square)
![License](https://img.shields.io/badge/license-Academic_Use_Only-red?style=flat-square)
![Test Executions](https://img.shields.io/badge/test_executions-74-blue?style=flat-square)
![MITRE Techniques](https://img.shields.io/badge/MITRE_techniques-25-orange?style=flat-square)
![Bypass Tests](https://img.shields.io/badge/bypass_tests-24-purple?style=flat-square)

</div>

---

## Technology Stack

<div align="center">

### Core Platform
![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.31.0-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-v29.4.0-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-Linux-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Kernel](https://img.shields.io/badge/Kernel-6.17.0--22-FCC624?style=for-the-badge&logo=linux&logoColor=black)

### CNI Plugins Under Test
![Calico](https://img.shields.io/badge/Calico-v3.28.0_iptables_mode-FC6A1B?style=for-the-badge&logoColor=white)
![Cilium](https://img.shields.io/badge/Cilium-eBPF_%2B_Hubble_enabled-F8C517?style=for-the-badge&logoColor=black)

### Tooling
![KIND](https://img.shields.io/badge/KIND-v0.24.0-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![kubectl](https://img.shields.io/badge/kubectl-v1.35.2-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![Helm](https://img.shields.io/badge/Helm-v3.x-0F1689?style=for-the-badge&logo=helm&logoColor=white)
![Cilium CLI](https://img.shields.io/badge/Cilium_CLI-v0.19.2-F8C517?style=for-the-badge&logoColor=black)

### Threat Framework and Target Workload
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Containers_v18.1-E31B23?style=for-the-badge&logoColor=white)
![Boutique](https://img.shields.io/badge/Google_Microservices_Demo-Online_Boutique-4285F4?style=for-the-badge&logo=google&logoColor=white)

### Scripting and Output
![Bash](https://img.shields.io/badge/Bash-Attack_%26_Bypass_Scripts-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![CSV](https://img.shields.io/badge/Output-CSV_%2B_TXT_Reports-217346?style=for-the-badge&logo=microsoftexcel&logoColor=white)

</div>

---

## What This Repository Contains

This repository holds every file needed to reproduce the dissertation research from scratch on a clean Ubuntu machine. It contains:

- KIND cluster configuration files for both test clusters
- CNI installation manifests and scripts for Calico and Cilium
- Default-deny NetworkPolicy manifest
- The full attack test suite and bypass test suite scripts
- Raw result files from all three test phases
- Performance benchmark data
- Observability capture data
- Data corrections documentation

**The dissertation document itself is submitted separately through the university portal.**

---

## Research Overview

This research empirically compared two production Kubernetes CNI plugins — **Calico** (iptables-based enforcement) and **Cilium** (eBPF-based enforcement with Hubble observability) — across three dimensions:

- **Enforcement effectiveness** against 25 MITRE ATT&CK for Containers techniques
- **Observability quality** for attack detection and incident response
- **Performance overhead** under identical workload conditions

Testing used two identical KIND clusters running Kubernetes v1.31.0 with the Google Online Boutique microservices application as the target workload. The CNI plugin was the sole independent variable.

---

## System Requirements

| Component | Minimum | Tested Value |
|---|---|---|
| Operating System | Ubuntu 22.04 LTS or later | Ubuntu Linux |
| Kernel | 5.15+ (eBPF support required) | 6.17.0-22-generic |
| RAM | 16 GB | 30 GB |
| Storage | 60 GB free | 492 GB NVMe SSD |
| CPU | 4 cores x86-64 | Multicore x86-64 |
| Internet | Required for image pulls | Required |

> Both clusters run simultaneously on the same host. Each cluster consumes approximately 6–8 GB RAM. Running below 16 GB will cause pods to be evicted or fail to schedule.

---

## Software Versions

| Tool | Version |
|---|---|
| Docker | 29.4.0 |
| KIND | 0.24.0 |
| kubectl | v1.35.2 client |
| Kubernetes | v1.31.0 (cluster) |
| Cilium CLI | v0.19.2 |
| Calico | v3.28.0 |
| Helm | 3.x |

---

## Repository Structure

```
K8s-CNI-policies/
│
├── README.md
│
├── clusters/
│   ├── kind-calico-cluster.yaml
│   └── kind-cilium-cluster.yaml
│
├── cni/
│   ├── calico/
│   │   ├── tigera-operator.yaml
│   │   └── calico-installation.yaml
│   └── cilium/
│       └── install-cilium.sh
│
├── policies/
│   └── default-deny-all.yaml
│
├── scripts/
│   ├── attack-test-suite.sh
│   ├── bypass-test-suite.sh
│   └── setup/
│       ├── 01-os-environment.sh
│       ├── 02-install-tools.sh
│       └── 03-deploy-boutique.sh
│
├── results/
│   ├── calico/
│   │   ├── phase1/
│   │   │   ├── kind-calico-cluster-phase1-20260418_113832.txt
│   │   │   └── kind-calico-cluster-phase1-20260418_113832.csv
│   │   ├── phase2/
│   │   │   ├── kind-calico-cluster-phase2-20260420_173652.txt
│   │   │   └── kind-calico-cluster-phase2-20260420_173652.csv
│   │   └── phase3-bypass/
│   │       ├── kind-calico-cluster-bypass-20260422_124120.txt
│   │       └── kind-calico-cluster-bypass-20260422_124120.csv
│   │
│   ├── cilium/
│   │   ├── phase1/
│   │   │   ├── kind-cilium-cluster-phase1-20260418_113909.txt
│   │   │   └── kind-cilium-cluster-phase1-20260418_113909.csv
│   │   ├── phase2/
│   │   │   ├── kind-cilium-cluster-phase2-20260420_174146.txt
│   │   │   └── kind-cilium-cluster-phase2-20260420_174146.csv
│   │   └── phase3-bypass/
│   │       ├── kind-cilium-cluster-bypass-20260422_124729.txt
│   │       └── kind-cilium-cluster-bypass-20260422_124729.csv
│   │
│   ├── performance/
│   │   ├── calico_throughput_no_policy.json
│   │   ├── calico_throughput_with_policy.json
│   │   ├── calico_latency_no_policy.json
│   │   ├── calico_latency_with_policy.json
│   │   ├── calico_throughput_cpu_run.json
│   │   ├── calico_cpu_overhead.txt
│   │   ├── cilium_throughput_no_policy.json
│   │   ├── cilium_throughput_with_policy.json
│   │   ├── cilium_latency_no_policy.json
│   │   ├── cilium_latency_with_policy.json
│   │   ├── cilium_throughput_cpu_run.json
│   │   └── cilium_cpu_overhead.txt
│   │
│   └── observability/
│       ├── hubble_attack_log.json
│       └── calico_iptables_state.txt
│
├── corrected/
│   ├── kindcalicoclusterphase2_corrected.csv
│   ├── kindciliumclusterphase2_corrected.csv
│   ├── kindcalicoclusterbypass_corrected.csv
│   └── kindciliumclusterbypass_corrected.csv
│
└── docs/
    ├── corrections.md
    └── mitre-technique-list.md
```

---

## Step-by-Step Reproduction Guide

Follow every step in order on a clean Ubuntu installation. Do not skip steps.

---

### Step 1 — Fix OS-Level Kernel Limits

KIND runs cluster nodes as Docker containers using full systemd. Without these fixes, KIND cluster creation will hang or fail silently.

```bash
# Apply inotify fixes
sudo sysctl fs.inotify.max_user_instances=512
sudo sysctl fs.inotify.max_user_watches=524288

# Make permanent across reboots
cat <<EOF | sudo tee /etc/sysctl.d/99-kind.conf
fs.inotify.max_user_instances = 512
fs.inotify.max_user_watches = 524288
EOF

sudo sysctl --system

# Configure Docker cgroup driver
sudo mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": { "max-size": "100m" },
  "storage-driver": "overlay2"
}
EOF

sudo systemctl daemon-reload
sudo systemctl restart docker
```

---

### Step 2 — Install All Required Tools

```bash
# Docker CE
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
sudo usermod -aG docker $USER && newgrp docker

# kubectl v1.31.0 — must match cluster version exactly
curl -LO "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# KIND v0.24.0
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Cilium CLI
CILIUM_CLI_VERSION=$(curl -s \
  https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
curl -L --fail --remote-name-all \
  https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
```

Verify:

```bash
docker --version       # expect: Docker version 29.x
kind --version         # expect: kind v0.24.0
kubectl version --client
helm version --short
cilium version
```

---

### Step 3 — Create Both KIND Clusters

```bash
# Calico cluster
cat <<EOF | kind create cluster --name kind-calico-cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/16"
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF

# Cilium cluster
cat <<EOF | kind create cluster --name kind-cilium-cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "10.245.0.0/16"
  serviceSubnet: "10.97.0.0/16"
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF
```

> Pod and Service CIDRs use non-overlapping ranges to prevent routing conflicts on the shared host.

Verify both clusters are running before continuing:

```bash
kubectl get nodes --context kind-calico-cluster
kubectl get nodes --context kind-cilium-cluster
# All nodes must show Ready status
```

---

### Step 4 — Install Calico on Cluster A

> **Critical:** Install the Tigera Operator first and wait for it to be ready before applying the Installation CR. The Operator must register the CRDs before the CR can be accepted.
> **Also critical:** Use `kubectl create`, not `kubectl apply`, for the Tigera Operator on Kubernetes v1.31.0.

```bash
# Step 4a — Install Tigera Operator
kubectl create -f \
  https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml \
  --context kind-calico-cluster

# Wait for operator to be ready
kubectl wait --for=condition=Available deployment/tigera-operator \
  -n tigera-operator --timeout=120s \
  --context kind-calico-cluster

# Step 4b — Apply Installation CR
cat <<EOF | kubectl apply --context kind-calico-cluster -f -
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    ipPools:
    - cidr: 10.244.0.0/16
      encapsulation: VXLANCrossSubnet
      natOutgoing: Enabled
      nodeSelector: all()
EOF

# Wait for Calico pods
watch kubectl get pods -n calico-system --context kind-calico-cluster
# Wait until all pods are Running
```

---

### Step 5 — Install Cilium with Hubble on Cluster B

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
  --version 1.14.0 \
  --namespace kube-system \
  --kube-context kind-cilium-cluster \
  --set image.pullPolicy=IfNotPresent \
  --set ipam.mode=kubernetes \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.enabled=true

# Wait for Cilium to be ready
cilium status --wait --context kind-cilium-cluster

# Enable Hubble
cilium hubble enable --context kind-cilium-cluster
```

---

### Step 6 — Deploy Google Microservices Demo

```bash
git clone https://github.com/GoogleCloudPlatform/microservices-demo.git
cd microservices-demo

# Deploy to Calico cluster
kubectl create namespace boutique --context kind-calico-cluster
kubectl apply -f release/kubernetes-manifests.yaml \
  -n boutique --context kind-calico-cluster

# Deploy to Cilium cluster
kubectl create namespace boutique --context kind-cilium-cluster
kubectl apply -f release/kubernetes-manifests.yaml \
  -n boutique --context kind-cilium-cluster
```

Wait for all pods to reach Running status (3–5 minutes on first pull):

```bash
kubectl get pods -n boutique --context kind-calico-cluster
kubectl get pods -n boutique --context kind-cilium-cluster
```

---

### Step 7 — Deploy Attacker Pod

```bash
# Calico cluster
kubectl run attacker-netshoot \
  --image=nicolaka/netshoot \
  --restart=Never -n boutique \
  --command -- sleep 3600 \
  --context kind-calico-cluster

# Cilium cluster
kubectl run attacker-netshoot \
  --image=nicolaka/netshoot \
  --restart=Never -n boutique \
  --command -- sleep 3600 \
  --context kind-cilium-cluster
```

---

### Step 8 — Run Phase 1 (Baseline — No Policy)

```bash
chmod +x scripts/attack-test-suite.sh

./scripts/attack-test-suite.sh kind-calico-cluster phase1
./scripts/attack-test-suite.sh kind-cilium-cluster phase1
```

---

### Step 9 — Apply Default-Deny NetworkPolicy

```bash
kubectl apply -f policies/default-deny-all.yaml \
  -n boutique --context kind-calico-cluster

kubectl apply -f policies/default-deny-all.yaml \
  -n boutique --context kind-cilium-cluster

# Verify
kubectl get networkpolicy -n boutique --context kind-calico-cluster
kubectl get networkpolicy -n boutique --context kind-cilium-cluster
```

---

### Step 10 — Run Phase 2 (Default-Deny Enforcement)

```bash
./scripts/attack-test-suite.sh kind-calico-cluster phase2
./scripts/attack-test-suite.sh kind-cilium-cluster phase2
```

---

### Step 11 — Run Phase 3 (CNI Bypass Testing)

```bash
chmod +x scripts/bypass-test-suite.sh

./scripts/bypass-test-suite.sh kind-calico-cluster
./scripts/bypass-test-suite.sh kind-cilium-cluster
```

---

### Preserving Cluster State Between Sessions

> KIND clusters do not survive Docker being stopped at the OS level. Always stop containers cleanly before shutting down.

```bash
# Before shutdown
docker stop $(docker ps -q --filter "name=kind")

# After restarting your machine
docker start $(docker ps -aq --filter "name=kind")
# Wait 60 seconds then verify
kubectl get nodes --context kind-calico-cluster
kubectl get nodes --context kind-cilium-cluster
```

---

## Test Script Usage Reference

```bash
# Attack test suite
./scripts/attack-test-suite.sh <cluster-context> <phase>

# phase options: phase1, phase2
./scripts/attack-test-suite.sh kind-calico-cluster phase1
./scripts/attack-test-suite.sh kind-cilium-cluster phase2

# Bypass test suite
./scripts/bypass-test-suite.sh <cluster-context>
./scripts/bypass-test-suite.sh kind-calico-cluster
```

Each script produces two output files per run:
- `.txt` — human-readable report with ALLOWED / BLOCKED / ERROR per technique
- `.csv` — structured data for analysis with timestamps

---

## Data Corrections

Two false positives were identified in the raw CSV output after testing was complete. Both were caused by the attack script classifier matching the substring `communications` inside a DNS timeout error message and incorrectly recording ALLOWED instead of BLOCKED.

| File | Technique | Raw Result | Corrected Result | Reason |
|---|---|---|---|---|
| Phase 2 — both clusters | T1071.004 | ALLOWED | BLOCKED | DNS query timed out; classifier triggered on error string |
| Phase 3 — both clusters | B22 | ALLOWED | BLOCKED | Identical DNS timeout pattern |

Original uncorrected files are preserved in `results/`. Corrected files are in `corrected/` with a `_corrected` suffix. Full documentation is in `docs/corrections.md`.

---

## Known Issues and Fixes

**Tigera Operator install fails on Kubernetes v1.31.0**
Use `kubectl create` not `kubectl apply` for the Tigera Operator manifest. See Step 4.

**KIND cluster creation hangs indefinitely**
Apply inotify kernel fixes in Step 1 before creating any clusters.

**Attacker pod ImagePullBackOff in Phase 3 (B01–B04)**
Under default-deny egress, the attacker pod image cannot be pulled from the registry. B01–B04 tests record ERROR in automated output. B01 was manually retested using a pre-staged image. See `docs/corrections.md` for full classification details.

**Cilium pods stuck in Init state**
Ensure all cluster nodes show Ready status before installing Cilium. If pods remain stuck after 3 minutes, delete and reinstall the Cilium DaemonSet.

---

## References

| Paper | DOI |
|---|---|
| Budigiri et al. 2021 — Network policies in Kubernetes | 10.1109/EuCNC/6GSummit51104.2021.9482526 |
| Kim et al. 2025 — Comparative security analysis of CNI plugins | 10.1109/ACCESS.2025.3543841 |
| Minna et al. 2021 — Security implications of Kubernetes networking | IEEE Security & Privacy vol. 19 no. 5 |
| Soldani et al. 2023 — eBPF cloud-native observability | 10.1109/ACCESS.2023.3281480 |
| MITRE ATT&CK for Containers v18.1 | attack.mitre.org/matrices/enterprise/containers |
| NSA/CISA Kubernetes Hardening Guidance | media.defense.gov 2022 |

---

## Licence

This repository is made available for academic reproducibility purposes. All scripts, configurations, and data files are original work produced for CT7P01 dissertation research at London Metropolitan University, May 2026.
