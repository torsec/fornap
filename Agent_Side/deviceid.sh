#!/bin/bash

URL="http://192.168.0.122:8081/deviceid"

# Update WhitelistID
DATA='{"Id": "13bcf5c0-cbce-4632-ac33-ae96757fcdb9"}'

curl -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d "$DATA"

echo "Data sent to $URL"