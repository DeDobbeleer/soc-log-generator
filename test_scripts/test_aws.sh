#!/bin/bash
# Test AWS CloudTrail sur SIEM
# Usage: ./test_aws.sh <IP_SIEM> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <IP_SIEM> [PORT]"
    echo "Exemple: $0 192.168.1.100 514"
    exit 1
fi

echo "=== TEST AWS CLOUDTRAIL ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: Format JSON (recommandé pour Splunk/Elastic)
echo "[TEST 1] Format JSON - 50 EPS pendant 60s..."
python3 -m soc_log_generator generate \
    --generator aws \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --syslog-format json \
    --eps 50 \
    --duration 60

echo ""
echo "[TEST 2] Multi-compte (5 clients parallèles)..."
python3 -m soc_log_generator generate \
    --generator aws \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --multi 5 \
    --eps 20 \
    --duration 30

echo ""
echo "[TEST 3] Scénario admin (création/suppression ressources)..."
python3 -m soc_log_generator generate \
    --generator aws \
    --eps 100 \
    --duration 60 \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT &
PID=$!
sleep 20
echo "  -> Vérifier détection changements IAM..."
sleep 20
echo "  -> Vérifier détection création EC2..."
wait $PID

echo ""
echo "=== TEST AWS COMPLETÉ ==="
echo "Vérifiez dans le SIEM:"
echo "- eventSource parsé (*.amazonaws.com)"
echo "- eventName (RunInstances, CreateUser, etc.)"
echo "- userIdentity.type (IAMUser, AssumedRole)"
echo "- awsRegion"
echo "- errorCode (si présent)"
