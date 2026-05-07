#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy-k8s.sh — Deploy Shadowbroker to a kind (or any) Kubernetes cluster
# ---------------------------------------------------------------------------
# Usage:
#   ./deploy-k8s.sh [--hostname <hostname>] [--tls-port <port>] [--skip-hosts]
#
# Options:
#   --hostname   Hostname for the Ingress (default: shadowbroker.local)
#   --tls-port   Host port Traefik HTTPS is bound to (default: 8443)
#   --skip-hosts Skip /etc/hosts update
# ---------------------------------------------------------------------------

HOSTNAME_VAR="${HOSTNAME_VAR:-shadowbroker.local}"
TLS_PORT="${TLS_PORT:-8443}"
SKIP_HOSTS=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
K8S_DIR="$SCRIPT_DIR/k8s"

# --- parse args ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname)   HOSTNAME_VAR="$2"; shift 2 ;;
    --tls-port)   TLS_PORT="$2";     shift 2 ;;
    --skip-hosts) SKIP_HOSTS=true;   shift   ;;
    *) echo "[!] Unknown argument: $1"; exit 1 ;;
  esac
done

echo "======================================================="
echo "   S H A D O W B R O K E R   —   k8s Deploy"
echo "======================================================="
echo "  Hostname : $HOSTNAME_VAR"
echo "  TLS port : $TLS_PORT"
echo ""

# --- preflight checks ------------------------------------------------------
echo "[*] Checking prerequisites..."

if ! command -v kubectl &>/dev/null; then
  echo "[!] kubectl not found. Install it from https://kubernetes.io/docs/tasks/tools/"
  exit 1
fi

if ! kubectl cluster-info &>/dev/null; then
  echo "[!] Cannot reach a Kubernetes cluster. Is your kubeconfig set up?"
  exit 1
fi

if ! command -v openssl &>/dev/null; then
  echo "[!] openssl not found. Install it to generate TLS certificates."
  exit 1
fi

echo "[+] Prerequisites OK"

# --- secret.yaml -----------------------------------------------------------
SECRET_FILE="$K8S_DIR/secret.yaml"
if [[ ! -f "$SECRET_FILE" ]]; then
  echo ""
  echo "[*] $SECRET_FILE not found — copying from example..."
  cp "$K8S_DIR/secret.yaml.example" "$SECRET_FILE"
  echo "[!] Edit $SECRET_FILE and fill in your API keys, then re-run this script."
  echo "    Required: ADMIN_KEY (all others can remain empty)"
  exit 1
fi

# --- TLS certificate -------------------------------------------------------
CERT_SECRET_EXISTS=$(kubectl get secret shadowbroker-tls -n shadowbroker --ignore-not-found -o name)

if [[ -z "$CERT_SECRET_EXISTS" ]]; then
  echo ""
  echo "[*] Generating self-signed TLS certificate for $HOSTNAME_VAR (10 years)..."
  TMP_DIR=$(mktemp -d)
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$TMP_DIR/tls.key" -out "$TMP_DIR/tls.crt" \
    -subj "/CN=$HOSTNAME_VAR" \
    -addext "subjectAltName=DNS:$HOSTNAME_VAR" 2>/dev/null

  # Ensure namespace exists before creating the secret
  kubectl create namespace shadowbroker --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  kubectl create secret tls shadowbroker-tls \
    --cert="$TMP_DIR/tls.crt" \
    --key="$TMP_DIR/tls.key" \
    -n shadowbroker \
    --dry-run=client -o yaml | kubectl apply -f -

  # Save cert for optional trust step
  cp "$TMP_DIR/tls.crt" "$SCRIPT_DIR/shadowbroker-ca.crt"
  rm -rf "$TMP_DIR"
  echo "[+] TLS secret created. Certificate saved to shadowbroker-ca.crt"
else
  echo "[*] TLS secret shadowbroker-tls already exists — skipping cert generation."
fi

# --- apply manifests -------------------------------------------------------
echo ""
echo "[*] Applying Kubernetes manifests..."
kubectl apply -k "$K8S_DIR/"
echo "[+] Manifests applied."

# --- /etc/hosts ------------------------------------------------------------
if [[ "$SKIP_HOSTS" == false ]]; then
  if grep -qF "$HOSTNAME_VAR" /etc/hosts 2>/dev/null; then
    echo "[*] /etc/hosts already contains $HOSTNAME_VAR — skipping."
  else
    echo ""
    echo "[*] Adding 127.0.0.1  $HOSTNAME_VAR to /etc/hosts (requires sudo)..."
    echo "127.0.0.1  $HOSTNAME_VAR" | sudo tee -a /etc/hosts >/dev/null
    echo "[+] /etc/hosts updated."
  fi
fi

# --- wait for rollout ------------------------------------------------------
echo ""
echo "[*] Waiting for backend rollout (this can take ~90s due to startup probes)..."
kubectl rollout status deployment/backend -n shadowbroker --timeout=180s

echo "[*] Waiting for frontend rollout..."
kubectl rollout status deployment/frontend -n shadowbroker --timeout=120s

# --- summary ---------------------------------------------------------------
echo ""
echo "======================================================="
echo "  Deploy complete!"
echo ""
echo "  URL  : https://$HOSTNAME_VAR:$TLS_PORT"
echo ""
echo "  To trust the certificate:"
if [[ "$(uname)" == "Darwin" ]]; then
  echo "    sudo security add-trusted-cert -d -r trustRoot \\"
  echo "      -k /Library/Keychains/System.keychain shadowbroker-ca.crt"
else
  echo "    sudo cp shadowbroker-ca.crt /usr/local/share/ca-certificates/shadowbroker.crt"
  echo "    sudo update-ca-certificates"
fi
echo ""
echo "  To remove everything:"
echo "    kubectl delete namespace shadowbroker"
echo "======================================================="
