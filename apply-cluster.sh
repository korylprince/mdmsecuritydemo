#!/bin/bash

# check that required parameters are set
if [ -z "$INGRESS_HOST" ]; then
    echo "INGRESS_HOST must be set"
    exit 1
fi

# get repo root
SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

# create prerequisite cluster operators
kubectl apply -f "$SCRIPT_DIR/k8s/cluster/operators/"
if [ $? -ne 0 ]; then
    echo "could not create cluster operators"
    exit 1
fi

# wait for namespaces to be created
namespaces=("cert-manager" "password-generator" "replicator")
for ns in "${namespaces[@]}" ; do
    kubectl wait "namespace/$ns" --for=create --timeout=60s
    if [ $? -ne 0 ]; then
        echo "timed out waiting for namespace/$ns to be created"
        exit 1
    fi
done

# wait for crds to be ready
crds=("middlewares.traefik.io" "serverstransports.traefik.io" "certificates.cert-manager.io" "clusterissuers.cert-manager.io" "stringsecrets.secretgenerator.mittwald.de")
for crd in "${crds[@]}" ; do
    kubectl wait "crd/$crd" --for=condition=established --timeout=60s
    if [ $? -ne 0 ]; then
        echo "timed out waiting for crd/$crd to be ready"
        exit 1
    fi
done

# create cluster issuer
kubectl kustomize "$SCRIPT_DIR/k8s/cluster/resources" | envsubst '$INGRESS_HOST' | kubectl apply -f -
if [ $? -ne 0 ]; then
    echo "could not create cluster resources"
    exit 1
fi

# deploy cluster services
kubectl kustomize "$SCRIPT_DIR/k8s/cluster/services" | envsubst '$INGRESS_HOST' | kubectl apply -f -
if [ $? -ne 0 ]; then
    echo "could not create cluster services"
    exit 1
fi

# wait for services to be available
kubectl wait -n registry deploy/registry-docker-registry --for=condition=available --timeout=60s
if [ $? -ne 0 ]; then
    echo "timed out waiting for registry:deploy/registry-docker-registry to be available"
    exit 1
fi

kubectl wait -n dashboard deploy/dashboard-kong --for=condition=available --timeout=60s
if [ $? -ne 0 ]; then
    echo "timed out waiting for dashboard:deploy/dashboard-kong to be available"
    exit 1
fi
