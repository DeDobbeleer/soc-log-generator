#!/bin/bash
# Windows Events Test on SIEM
# Usage: ./test_windows.sh <SIEM_IP> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <SIEM_IP> [PORT]"
    echo "Example: $0 192.168.1.100 514"
    exit 1
fi

echo "=== WINDOWS EVENTS TEST ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: Basic
echo "[TEST 1] Sending 100 events/sec for 30s..."
python3 -m soc_log_generator generate \
    --generator windows \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --eps 100 \
    --duration 30

echo ""
echo "[TEST 2] JSON format..."
python3 -m soc_log_generator generate \
    --generator windows \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-format json \
    --eps 50 \
    --duration 20

echo ""
echo "[TEST 3] Load spike (burst)..."
python3 -m soc_log_generator generate \
    --generator windows \
    --mode burst \
    --start-eps 10 \
    --eps 500 \
    --ramp-time 15 \
    --duration 30 \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT

echo ""
echo "=== WINDOWS TEST COMPLETED ==="
echo "Verify in SIEM:"
echo "- Events received (approx 6,500)"
echo "- Channel (Security/System/Application)"
echo "- EventID recognized"
echo "- Severity mapping"
