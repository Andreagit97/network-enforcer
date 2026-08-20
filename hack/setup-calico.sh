#!/usr/bin/env bash

set -eu

CALICO_VERSION="v3.32.1"
NETWORK_ENFORCER_NAMESPACE="${NETWORK_ENFORCER_NAMESPACE:-network-enforcer}"
GOLDMANE_CLIENT_SECRET="net-enf-goldmane-client-certs"

helm repo add projectcalico https://docs.tigera.io/calico/charts
helm repo update

printf "\n- 🚀 Create calico-system namespace:\n"
# we don't want to fail in case of an existing namespace
kubectl create namespace calico-system --dry-run=client -o yaml | kubectl apply -f -

# Install the CRD first
printf "\n- 🚀 Install Calico CRDs:\n"
helm template calico-crds projectcalico/crd.projectcalico.org.v1 --version $CALICO_VERSION | kubectl apply --server-side -f -

printf "\n- 🚀 Deploy tigera-operator:\n"
# As a dataplane for now we use the default one: Iptables # https://github.com/projectcalico/calico/blob/58949447b523cd9ed372c7cbcf3601c027fa80d8/charts/tigera-operator/values.yaml#L48
# To enable trace logs in calico:
# --set 'defaultFelixConfiguration.enabled=true'
# --set 'defaultFelixConfiguration.logSeverityScreen=Trace'
helm upgrade --install calico projectcalico/tigera-operator \
  --version $CALICO_VERSION \
  --namespace tigera-operator \
  --create-namespace \
  --wait --timeout 10m \
  --set installation.enabled=true \
  --set apiServer.enabled=true \
  --set goldmane.enabled=true \
  --set whisker.enabled=false \
  --set 'installation.calicoNetwork.ipPools[0].name=default-ipv4-ippool' \
  --set 'installation.calicoNetwork.linuxDataplane=Iptables' \
  --set 'installation.calicoNetwork.ipPools[0].cidr=10.244.0.0/16' # `10.244.0.0/16` is the default Kind Cluster CIDR

# Wait for the Goldmane certificates to be created
printf "\n- 🚀 Wait for goldmane resources to be created:\n"
kubectl wait --for=create -n calico-system configmap/goldmane-ca-bundle --timeout=120s
kubectl wait --for=create -n calico-system secret/goldmane-key-pair --timeout=120s

# Wait for goldmane deployment to be ready, this is needed by the controller to scrape flows
kubectl wait --for=condition=Available deployment/goldmane -n calico-system --timeout=300s

# Create the secret for the controller's Goldmane scraper
printf "\n- 🚀 Creating Goldmane client secret:\n"
kubectl create namespace "$NETWORK_ENFORCER_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic "$GOLDMANE_CLIENT_SECRET" \
  --from-file=ca.crt=<(kubectl -n calico-system get configmap goldmane-ca-bundle -o jsonpath='{.data.tigera-ca-bundle\.crt}') \
  --from-file=tls.crt=<(kubectl -n calico-system get secret goldmane-key-pair -o jsonpath='{.data.tls\.crt}' | base64 -d) \
  --from-file=tls.key=<(kubectl -n calico-system get secret goldmane-key-pair -o jsonpath='{.data.tls\.key}' | base64 -d) \
  -n "$NETWORK_ENFORCER_NAMESPACE" \
  --dry-run=client -o yaml | kubectl apply -f -
