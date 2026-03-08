#!/bin/bash
# Test Windows Events sur SIEM
# Usage: ./test_windows.sh <IP_SIEM> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <IP_SIEM> [PORT]"
    echo "Exemple: $0 192.168.1.100 514"
    exit 1
fi

echo "=== TEST WINDOWS EVENTS ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""

# Test 1: Basique
echo "[TEST 1] Envoi 100 events/sec pendant 30s..."
python3 -m soc_log_generator generate \
    --generator windows \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-protocol tcp \
    --eps 100 \
    --duration 30

echo ""
echo "[TEST 2] Format JSON..."
python3 -m soc_log_generator generate \
    --generator windows \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT \
    --syslog-format json \
    --eps 50 \
    --duration 20

echo ""
echo "[TEST 3] Pic de charge (burst)..."
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
echo "=== TEST WINDOWS COMPLETÉ ==="
echo "Vérifiez dans le SIEM:"
echo "- Events reçus (environ 6,500)"
echo "- Channel (Security/System/Application)"
echo "- EventID reconnu"
echo "- Severity mapping"
