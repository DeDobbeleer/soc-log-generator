#!/bin/bash
# Test Firewall sur SIEM
# Usage: ./test_firewall.sh <IP_SIEM> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <IP_SIEM> [PORT]"
    echo "Exemple: $0 192.168.1.100 514"
    exit 1
fi

echo "=== TEST FIREWALL ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: CEF (pour ArcSight/QRadar)
echo "[TEST 1] Format CEF - 1000 EPS pendant 60s..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --syslog-format cef \
    --eps 1000 \
    --duration 60

echo ""
echo "[TEST 2] Format JSON (Splunk/Elastic)..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-format json \
    --eps 500 \
    --duration 30

echo ""
echo "[TEST 3] Test de charge soutenue..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --eps 5000 \
    --duration 300 &
PID=$!
echo "  -> Génération 5000 EPS pendant 5 minutes (PID: $PID)"
echo "  -> Surveiller CPU/Mémoire SIEM..."
wait $PID

echo ""
echo "=== TEST FIREWALL COMPLETÉ ==="
echo "Vérifiez dans le SIEM:"
echo "- App ID (app)"
echo "- Zones (src/dst)"
echo "- Action (allow/deny)"
echo "- Bytes/packets"
echo "- Session ID"
echo "- Category"
