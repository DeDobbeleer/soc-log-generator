#!/bin/bash
# Test de charge complet sur SIEM
# Usage: ./test_stress.sh <IP_SIEM> [PORT]

SIEM_IP=${1:-}
PORT=${2:-514}

if [ -z "$SIEM_IP" ]; then
    echo "Usage: $0 <IP_SIEM> [PORT]"
    exit 1
fi

echo "=== TEST DE CHARGE SIEM ==="
echo "SIEM: $SIEM_IP:$PORT"
echo ""
echo "ATTENTION: Ce test génère beaucoup de trafic!"
read -p "Continuer? (oui/non): " CONFIRM
if [ "$CONFIRM" != "oui" ]; then
    exit 0
fi

LOG_DIR="stress_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p $LOG_DIR

echo ""
echo "[TEST 1] Ramp up progressif..."
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
echo "[TEST 2] Burst traffic (simulation DDoS)..."
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
echo "[TEST 3] Multi-source (tous les générateurs)..."

# Lancer tous les générateurs en parallèle
python3 -m soc_log_generator generate --generator windows --eps 50 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/windows.log 2>&1 &
python3 -m soc_log_generator generate --generator linux --eps 50 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/linux.log 2>&1 &
python3 -m soc_log_generator generate --generator firewall --eps 1000 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/firewall.log 2>&1 &
python3 -m soc_log_generator generate --generator aws --eps 100 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/aws.log 2>&1 &
python3 -m soc_log_generator generate --generator azure --eps 100 --duration 60 --syslog-host $SIEM_IP --syslog-port $PORT > $LOG_DIR/azure.log 2>&1 &

echo "  -> Tous les générateurs lancés (60 secondes)..."
wait
echo "  -> Terminé"

echo ""
echo "=== TEST DE CHARGE COMPLETÉ ==="
echo "Logs sauvegardés dans: $LOG_DIR/"
echo ""
echo "Vérifiez dans le SIEM:"
echo "- Aucune perte d'events"
echo "- Latence d'ingestion acceptable"
echo "- Pas de buffering/fille d'attente"
echo "- CPU/Mémoire stables"
