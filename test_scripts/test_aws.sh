#!/bin/bash
# AWS CloudTrail Test on SIEM
# Usage: ./test_aws.sh <SIEM_IP> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <SIEM_IP> [PORT]"
    echo "Example: $0 192.168.1.100 514"
    exit 1
fi

echo "=== AWS CLOUDTRAIL TEST ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: JSON format (recommended for Splunk/Elastic)
echo "[TEST 1] JSON format - 50 EPS for 60s..."
python3 -m soc_log_generator generate \
    --generator aws \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --syslog-format json \
    --eps 50 \
    --duration 60

echo ""
echo "[TEST 2] Multi-account (5 parallel clients)..."
python3 -m soc_log_generator generate \
    --generator aws \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --multi 5 \
    --eps 20 \
    --duration 30

echo ""
echo "[TEST 3] Admin scenario (resource creation/deletion)..."
python3 -m soc_log_generator generate \
    --generator aws \
    --eps 100 \
    --duration 60 \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT &
PID=$!
sleep 20
echo "  -> Check IAM change detection..."
sleep 20
echo "  -> Check EC2 creation detection..."
wait $PID

echo ""
echo "=== AWS TEST COMPLETED ==="
echo "Verify in SIEM:"
echo "- eventSource parsed (*.amazonaws.com)"
echo "- eventName (RunInstances, CreateUser, etc.)"
echo "- userIdentity.type (IAMUser, AssumedRole)"
echo "- awsRegion"
echo "- errorCode (if present)"
