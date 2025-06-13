#!/bin/bash

# check that required parameters are set
if [ -z "$INGRESS_HOST" ]; then
    echo "INGRESS_HOST must be set"
    exit 1
fi

# select podman or docker
CMD=podman
if [ ! -x "$(command -v podman)" ]; then
    if [ ! -x "$(command -v docker)" ]; then
        echo "podman or docker commands not found"
    fi
    CMD=docker
fi

# sign into registry
USERNAME=admin
PASSWORD=$(kubectl get -n registry secrets/basic-auth --template='{{.data.password | base64decode}}')

if [ $? -ne 0 ]; then
    echo "could not get registry password"
    exit 1
fi

$CMD login -u "$USERNAME" -p "$PASSWORD" "registry.$INGRESS_HOST"
if [ $? -ne 0 ]; then
    echo "could not get sign into registry.$INGRESS_HOST"
    exit 1
fi

# get repo root
SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

containers=("dynamicacme" "deviceinventory" "enrollhandler" "nanowebhook")
if [ ! -z "$1" ]; then
    containers=("$1")
fi

# build and push containers
for container in "${containers[@]}" ; do
    IMAGE_TAG=$(cat "$SCRIPT_DIR/$container/IMAGE_TAG")
    if [ $? -ne 0 ]; then
        echo "could not get tag from $SCRIPT_DIR/$container/IMAGE_TAG"
        exit 1
    fi

    IMAGE="registry.${INGRESS_HOST}/${container}:$IMAGE_TAG"

    $CMD build --platform=linux/amd64 -t "$IMAGE" "$SCRIPT_DIR/${container}"
    if [ $? -ne 0 ]; then
        echo "could not build $container"
        exit 1
    fi
    
    $CMD push "$IMAGE"
    if [ $? -ne 0 ]; then
        echo "could not push $IMAGE"
        exit 1
    fi
done
