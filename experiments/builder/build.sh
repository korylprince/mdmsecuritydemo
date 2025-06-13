#!/bin/bash

SOURCE="$1"
TAG="$2"

print_help () {
  echo "Usage: build.sh <source folder> <image tag>"
}

if [[ -z "$NAMESPACE" ]]; then
    NAMESPACE="container-build"
fi

# check inputs
if [[ -z "$SOURCE" ]]; then
    print_help
    exit 1
fi

if [[ -z "$TAG" ]]; then
    print_help
    exit 1
fi

# check for Dockerfile
if [[ ! -f "$SOURCE/Dockerfile" ]]; then
    echo "Dockerfile not found in $SOURCE"
    exit 1
fi

# create namespace if it doesn't exist
kubectl get namespace "$NAMESPACE" > /dev/null

if [[ $? -ne 0 ]]; then
    kubectl create namespace "$NAMESPACE"
    if [[ $? -ne 0 ]]; then
        echo "could not create namespace $NAMESPACE"
        exit 1
    fi
fi


# generate name
NAME="build-$(openssl rand -hex 4)"

echo "starting job: $NAME"

cat <<EOF | kubectl apply -f - > /dev/null
---
apiVersion: batch/v1
kind: Job
metadata:
  name: '$NAME'
  namespace: '$NAMESPACE'
spec:
  template:
    spec:
      initContainers:
      - name: upload
        image: busybox:stable
        command:
          - /bin/sh
          - -c
          - 'while true; do sleep 1; if [ -f /.uploaddone ] ; then break; fi done'
        volumeMounts:
        - name: workspace
          mountPath: /workspace
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
          - --context=/workspace
          - '--destination=$TAG'
        volumeMounts:
        - name: workspace
          mountPath: /workspace
      volumes:
        - name: workspace
          emptyDir: {}
      restartPolicy: Never
  backoffLimit: 1
EOF

if [[ $? -ne 0 ]]; then
    echo "kubectl apply failed"
    exit 1
fi

# get pod name
POD=$(kubectl get pods -n "$NAMESPACE" --selector=job-name=$NAME -o="jsonpath={.items[0].metadata.name}")
echo "pod started: $POD"

# wait for upload container to start
echo "waiting for upload container to start"
kubectl wait -n "$NAMESPACE" "pod/$POD" --for='jsonpath={.status.initContainerStatuses[?(@.name=="upload")].started}=true' > /dev/null
if [[ $? -ne 0 ]]; then
    exit 1
fi

# upload workspace
echo "uploading workspace: $SOURCE"
kubectl cp -n "$NAMESPACE" "$SOURCE/." "$POD:/workspace" -c upload

if [[ $? -ne 0 ]]; then
    echo "uploading workspace failed"
    exit 1
fi

# trigger init container to finish
echo "completing upload"
kubectl exec -n "$NAMESPACE" "$POD" -c upload -- touch /.uploaddone

if [[ $? -ne 0 ]]; then
    echo "completing upload failed"
    exit 1
fi

# show logs
echo "waiting for kaniko to start"
kubectl wait -n "$NAMESPACE" "pod/$POD" --for='jsonpath={.status.containerStatuses[?(@.name=="kaniko")].ready}=true' > /dev/null
if [[ $? -ne 0 ]]; then
    exit 1
fi

echo "streaming build logs"
kubectl logs -f -n "$NAMESPACE" "$POD" -c kaniko
