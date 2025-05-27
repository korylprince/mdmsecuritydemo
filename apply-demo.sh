#!/bin/bash

# check that required parameters are set
if [ -z "$INGRESS_HOST" ]; then
    echo "INGRESS_HOST must be set"
    exit 1
fi

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

# create demo services
kubectl kustomize "$SCRIPT_DIR/k8s/demo" | envsubst '$INGRESS_HOST' | kubectl apply -f -
