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
    - `docker login registry-<cluster.tld>`
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

If you're deploying a new image to an existing container, you must do one of the following to have the container use the new image:

- Use a different image tag, update the yaml file, and run `kubectl apply -f <yaml>`
- If you use the same image tag as before, you'll need to run `kubectl rollout restart -n <namespace> deploy/<deploy name>`
    - This requires that ImagePullPolicy is set to Always on the container spec. Otherwise it won't check if the image changed
- Delete the deploy and reapply the yaml:
    - `kubectl delete deploy -n <namespace> <deploy name>`
    - `kubectl apply -f file.yaml`

## Deploy services

Now that all of our dependencies are installed and our service containers are built, it's time to deploy all of the services:

```bash
kubectl apply -f ./k8s
```

FIXME: demo functionality

# Configure DEP profiles (NanoDEP)

Follow the NanoDEP docs to [set up your environment](https://github.com/micromdm/nanodep/blob/main/docs/quickstart.md#setup-environment):

```bash
export BASE_URL='https://<cluster.tld>'
export APIKEY=$(kubectl get -n nanodep secrets/api-key --template='{{.data.password | base64decode}}')
export DEP_NAME=mdm
```

Continue following the NanoDEP docs to

- [generate and retrieve the DEP token public key](https://github.com/micromdm/nanodep/blob/main/docs/quickstart.md#generate-and-retrieve-the-dep-token-public-key)
- [download your DEP token](https://github.com/micromdm/nanodep/blob/main/docs/quickstart.md#download-token)
- [decrypt and upload it](https://github.com/micromdm/nanodep/blob/main/docs/quickstart.md#decrypt-tokens)
- [assign devices in the portal](https://github.com/micromdm/nanodep/blob/main/docs/quickstart.md#assign-a-device-in-the-portal)

Now create your DEP profile:

```json
{
  "profile_name": "My Cool MDM",
  "url": "https://<cluster.tld>/mdm/enroll",
  "configuration_web_url": "https://<cluster.tld>/mdm/enroll",
  "is_supervised": true,
  "is_mandatory": true,
  "is_mdm_removable": true,
  "await_device_configured": false,
  "org_magic": "AD5A973D-A4D4-405C-AD4E-7A7EFA5095A6",
  "skip_setup_items": [
    "AppleID",
    "DisplayTone",
    "Privacy",
    "FileVault",
    "iCloudDiagnostics",
    "iCloudStorage",
    "Restore",
    "ScreenTime",
    "Siri"
  ],
  "devices": ["serial1", "serial2"]
}
```

Finally, assign the profile:

```bash
/path/to/nanodep_repo/tools/dep-define-profile.sh /path/to/dep_profile.json

# output:
{"profile_uuid":"EA75919B46644054A32B940C3B8AD094","devices":{"serial1":"SUCCESS","serial2":"SUCCESS"}}
```

**Note:** the default ingress match rule only exposes a limited subset of the [reverse proxy API](https://github.com/micromdm/nanodep/blob/main/docs/operations-guide.md#reverse-proxy), so some of the nanodep tools will return a "404 not found" message. Follow the comments in [nanodep.yaml](./k8s/nanodep.yaml) to fully expose the API.
