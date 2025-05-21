# About

TBD

Components:
TBD


# Kubernetes (k8s) cluster setup

## FIXME: move to a helm chart to parameterize hostname, IP, etc

This demo is running on a single-node [k3s](https://k3s.io/) cluster. Follow these steps to set up a k3s cluster yourself:

## Initial cluster setup

1. [Install kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl):
1. [Install k3s](https://docs.k3s.io/installation):
    - On a linux server (we used Ubuntu 22.04):
        - `curl -sfL https://get.k3s.io | sh -`
    - See the [k3d project](https://k3d.io/stable/) for running k3s in Docker on other OSes - this setup is untested for this demo
1.  Port-forward the k8s API port to your local device:
    - `ssh -L 6443:localhost:6443 user@yourserver.tld`
    - Keep this connection open to use kubectl locally, or use `k3s kubectl ...` directly on your server
1. Copy kubectl config to your local device
    - Copy `/etc/rancher/k3s/k3s.yaml` from your server to `~/.kube/config` on your local device
1. Verify kubectl connectivity:
    - `kubectl get pods -A` should return several running pods

TBD: DNS records

## Cluster dependencies

Install these dependencies on your new cluster so you can deploy the demo in the next step.

Install each dependency in order using `kubectl apply -f path/to/file.yaml`

// cert-manager.yaml       https-cert.yaml         lb.yaml                 letsencrypt-issuer.yaml password-generator.yaml registry-password.yaml  registry.yaml           replicator.yaml
1. [password-generator.yaml](./k8s/cluster/password-generator.yaml)
    - Installs [a k8s operator](https://github.com/mittwald/kubernetes-secret-generator) that generates secrets (passwords, basic auth credentials, etc)
1. [replicator.yaml](./k8s/cluster/replicatoryaml)
    - Installs [a k8s operator](https://github.com/mittwald/kubernetes-replicator) that replicates secrets between namespaces (to share certificates and passwords between namespaces)
1. [lb.yaml](./k8s/cluster/lb.yaml)
    - Configures the [built-in Traefik Ingress controller](https://docs.k3s.io/networking/networking-services#traefik-ingress-controller) to use the real client IPs and adds http-redirection and internal-only middleware
1. [cert-manager.yaml](./k8s/cluster/cert-manager.yaml)
    - Installs [a k8s operator](https://cert-manager.io/) that supports generating PKI (CAs, certs, etc) including from Let's Encrypt
1. [letsencrypt-issuer.yaml](./k8s/cluster/letsencrypt-issuer.yaml)
    - Configures a Let's Encrypt cert-manager issuer
1. [https-cert.yaml](./k8s/cluster/https-cert.yaml)
    - Requests a certificate from Let's Encrypt that is shared with other services
    - To use Let's Encrypt automatic certificates, your k8s cluster must have a public IP, and you must have a domain with DNS pointed at the server
        - If you don't have a server with a public IP, using the [DNS-01 challenge](https://cert-manager.io/docs/configuration/acme/dns01/) might be an alternative
1. Optional - [registry-password.yaml](./k8s/cluster/registry-password.yaml)
    - Generates basic auth for a cluster-hosted container registry
1. Optional - [registry.yaml](./k8s/cluster/replicatoryaml)
    - Installs a container registry to the cluster for private container image hosting
1. Optional - [dashboard.yaml](./k8s/cluster/dashboard.yaml)
    - Installs [Kubernetes Dashboard](https://github.com/kubernetes/dashboard)
    - To access:
        - Run `kubectl -n dashboard create token admin` and copy token
        - Visit https://dashboard.<cluster.tld>
        - Enter token in login box

## Build and push containers

This demo deploys some services from public container repos (e.g. Docker Hub and ghcr.io), but others are built from code in this repo.

We deployed a private container registry in the cluster above so we can build and push images directly to the cluster (though hosting these in a public container repo works too!).

Before deploying the demo services, build and push these images: (FIXME: add instructions for all services).

1. Sign into container registry
    - `docker login`
        - username: admin
        - password: `kubectl get -n registry secrets/basic-auth --template='{{.data.password | base64decode}}'`
1. Build container images
    - Example:
        - `docker build --platform=linux/amd64 -t registry.<cluster.tld>/dynamicacme:1 dynamicacme`
1. Push container image
    - Example:
        - `docker push registry.<cluster.tld>/dynamicacme:1`
1. Use container image
    - Configure the image as `registry-internal.<cluster.tld>/dynamicacme:1` in the container spec
    - `registry-internal.<cluster.tld>` requires no auth and can be accessed only from the cluster host itself

## Deploy services

Now that all of our dependencies are installed and our service containers are built, it's time to deploy all of the services:

```bash
kubectl apply -f ./k8s
```

FIXME: demo functionality
