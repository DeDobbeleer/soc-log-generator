#!/bin/bash
# Firewall Test on SIEM
# Usage: ./test_firewall.sh <SIEM_IP> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <SIEM_IP> [PORT]"
    echo "Example: $0 192.168.1.100 514"
    exit 1
fi

echo "=== FIREWALL TEST ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: CEF (for ArcSight/QRadar)
echo "[TEST 1] CEF format - 1000 EPS for 60s..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --syslog-format cef \
    --eps 1000 \
    --duration 60

echo ""
echo "[TEST 2] JSON format (Splunk/Elastic)..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-format json \
    --eps 500 \
    --duration 30

echo ""
echo "[TEST 3] Sustained load test..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --eps 5000 \
    --duration 300 &
PID=$!
echo "  -> Generating 5000 EPS for 5 minutes (PID: $PID)"
echo "  -> Monitor SIEM CPU/Memory..."
wait $PID

echo ""
echo "=== FIREWALL TEST COMPLETED ==="
echo "Verify in SIEM:"
echo "- App ID (app)"
echo "- Zones (src/dst)"
echo "- Action (allow/deny)"
echo "- Bytes/packets"
echo "- Session ID"
echo "- Category"
