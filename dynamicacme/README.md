# About

This is a POC server to support dynamic (e.g. single use) secrets for ACME certificate requests, similar to [MicroMDM's dynamic SCEP support](https://github.com/micromdm/scep/blob/main/challenge/challenge.go).

WARNING: Use this as a jumping off point, not in production.

# Configuration

This service expects the following environment variables to be configured:

- `$API_KEY`: The bearer token that should be passed to the /api/key endpoint
- `$WEBHOOK_KEY`: The bearer token that should be passed to the /webhook endpoint
- `$TLS_CERT_PATH`: The path to the TLS certificate for the service
- `$TLS_KEY_PATH`: The path to the matching TLS key for the service
- `$DEBUG_KEY`: A static profile key that will always be accepted by the webhook if set

Note: the webhook must listen on HTTPS using a cert signed by step-ca's root CA.

## step-ca

smallstep step-ca is configured to point at this webhook:

```bash
/usr/local/bin/step ca provisioner webhook add <provisioner name> webhook \
--bearer-token-file /etc/smallstep/keys/webhook-key \ # contains $WEBHOOK_KEY
--url 'https://<webhook host>/webhook'
# other flags to authorize request (see k8s smallstep.yaml)
# this command also prints out a secret key that can be used to further authorize the webhook request from smallstep
# see https://smallstep.com/docs/step-ca/webhooks/#authentication
```

# API

This service has two endpoints:

## POST /api/key

This endpoint is called by another service that generates enrollment profiles, to get a dynamic secret:

```curl
POST /api/key
Authorization: Bearer $API_KEY

{"key":"amWtEJljTRdpFc29Ej2CtjX0ch_BQN07WXmb4nWRO08"}
```

This returned key would then be embedded in a dynamically generated ACME payload, Subject 2.5.4.35 field:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>ClientIdentifier</key>
            <string>$SERIAL_NUMBER</string>
            <key>Attest</key>
            <true/>
            <key>HardwareBound</key>
            <true/>
            <key>KeySize</key>
            <integer>384</integer>
            <key>KeyType</key>
            <string>ECSECPrimeRandom</string>
            -- snip --
            <key>Subject</key>
            <array>
                -- snip --
                <array>
                    <array>
                        <!-- set dynamic key -->
                        <string>2.5.4.35</string>
                        <string>amWtEJljTRdpFc29Ej2CtjX0ch_BQN07WXmb4nWRO08</string>
                    </array>
                </array>
            </array>
            -- snip --
            <key>DirectoryURL</key>
            <string>https://acme.example.com/acme</string>
        </dict>
    </array>
    -- snip --
    <key>PayloadIdentifier</key>
    <string>com.example.myprofile</string>
</dict>
</plist>
```

See [Apple's documentation](https://developer.apple.com/documentation/devicemanagement/acmecertificate) for more information configuring this payload.

## POST /webhook

This endpoint is [called by smallstep step-ca](https://smallstep.com/docs/step-ca/webhooks/) to authorize a certificate request. The request is allowed if the request includes a key returned by the `/api/key` endpoint in the last 5 minutes.

```curl
POST /webhook
Authorization: Bearer $WEBHOOK_KEY

{"allow": true, "data": {}}
```
