#!/bin/bash

URL="http://192.168.0.122:8081/attestationresult"

# Update DeviceID for whom the attestation result is requested
DATA='{"Id": "dad2e04e-4396-4048-a186-9ed60d84500b"}'

curl -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d "$DATA"

echo "Data sent to $URL"