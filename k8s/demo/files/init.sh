#!/bin/bash
set -euxo pipefail

# only run the init if the step ca config doesn't already exist
if [ ! -f "${STEPPATH}/config/ca.json" ]; then
    /usr/local/bin/step ca init \
      --root=/etc/smallstep/ca.crt \
      --key=/etc/smallstep/tls.key \
      --deployment-type=standalone \
      --remote-management \
      --name=smallstep \
      --provisioner=admin \
      --dns=localhost \
      --dns=smallstep \
      --dns=smallstep.smallstep \
      --address=:443 \
      --acme \
      --password-file=/etc/smallstep/passwords/provisioner-password

  # start server for config changes
  /usr/local/bin/step-ca /data/config/ca.json --password-file=/etc/smallstep/passwords/provisioner-password &
  sleep 5

  # configure acme device challenge
  /usr/local/bin/step ca provisioner update acme \
    --admin-subject=step --admin-provisioner=admin --admin-password-file=/etc/smallstep/passwords/provisioner-password \
    --ca-url=https://localhost:443 --challenge=device-attest-01 --attestation-format=apple \
    --x509-template=/etc/smallstep/templates/template.json

  # configure webhook to use dynamicacme service
  /usr/local/bin/step ca provisioner webhook add acme webhook \
    --admin-subject=step --admin-provisioner=admin --admin-password-file=/etc/smallstep/passwords/provisioner-password \
    --bearer-token-file /etc/smallstep/keys/webhook-key \
    --url 'https://dynamicacme.dynamicacme/webhook'

  # create config map from intermediate cert for nanomdm
  cat > /tmp/intermediate.yaml <<EOF
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: intermediate-ca
    namespace: nanomdm
  binaryData:
    intermediate.crt: "$(cat /data/certs/intermediate_ca.crt | base64 -w 0)"
EOF

  # apply config map
  curl --cacert /run/secrets/kubernetes.io/serviceaccount/ca.crt \
    -X PATCH \
    -H "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)" \
    -H "Content-Type: application/apply-patch+yaml" \
    --data-binary @/tmp/intermediate.yaml \
    https://kubernetes.default.svc/api/v1/namespaces/nanomdm/configmaps/intermediate-ca?fieldManager=curl

else
  echo "config exists"
fi
