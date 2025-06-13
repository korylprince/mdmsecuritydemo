# About

This is a small device inventory service to simulate an external device inventory.

# Configuration

This service expects the following environment variables to be configured:

- `$API_KEY`: The bearer token that should be passed to the /devices/query endpoint
- `$INVENTORY_PATH`: The path to a file containing newline-separated serial numbers or UDIDs

# API

This service has a single endpoint:

## POST /devices/query

This endpoint is called by other services to check if a serial number or UDID is in the device inventory.

```curl
POST /devices/query
Authorization: Bearer $API_KEY

{"serial_number":"ABC123", "udid": "C5A76DE3-1729-4126-9E74-019655FF3ABC"}
```
