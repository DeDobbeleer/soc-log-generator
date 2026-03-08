#!/bin/bash
# Complete SIEM Load Test
# Usage: ./test_stress.sh <SIEM_IP> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <SIEM_IP> [PORT]"
    exit 1
fi

echo "=== SIEM LOAD TEST ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""
echo "WARNING: This test generates heavy traffic!"
read -p "Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    exit 0
fi

LOG_DIR="stress_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p $LOG_DIR

echo ""
echo "[TEST 1] Progressive ramp up..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --mode ramp \
    --start-eps 100 \
    --eps 10000 \
    --ramp-time 300 \
    --duration 600 \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT 2>&1 | tee $LOG_DIR/ramp_test.log

echo ""
echo "[TEST 2] Burst traffic (DDoS simulation)..."
python3 -m soc_log_generator generate \
    --generator firewall \
    --mode burst \
    --start-eps 1000 \
    --eps 20000 \
    --ramp-time 60 \
    --duration 180 \
    --syslog-host $SIEM_IP \
    --syslog-port $PORT 2>&1 | tee $LOG_DIR/burst_test.log

echo ""
echo "[TEST 3] Multi-source (all generators)..."

# Launch all generators in parallel
python3 -m soc_log_generator generate --generator windows --eps 50 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/windows.log 2>&1 &
python3 -m soc_log_generator generate --generator linux --eps 50 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/linux.log 2>&1 &
python3 -m soc_log_generator generate --generator firewall --eps 1000 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/firewall.log 2>&1 &
python3 -m soc_log_generator generate --generator aws --eps 100 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/aws.log 2>&1 &
python3 -m soc_log_generator generate --generator azure --eps 100 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/azure.log 2>&1 &

echo "  -> All generators launched (60 seconds)..."
wait
echo "  -> Completed"

echo ""
echo "=== LOAD TEST COMPLETED ==="
echo "Logs saved in: $LOG_DIR/"
echo ""
echo "Verify in SIEM:"
echo "- No event loss"
echo "- Acceptable ingestion latency"
echo "- No buffering/queue issues"
echo "- Stable CPU/Memory"
