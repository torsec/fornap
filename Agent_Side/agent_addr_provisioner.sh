#!/bin/bash

URL="http://192.168.0.122:8080/agentaddr"

# IP and PORT on which the Agent is waiting to be contacted
DATA='{"Ip": "192.168.0.103", "Port": 8081}'

curl -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d "$DATA"

echo "Data sent to $URL"