# SIEM Test Scripts

## Prerequisites

```bash
# Make scripts executable
chmod +x test_*.sh

# Verify generator is installed
python3 -m soc_log_generator --version
```

## Usage

### Windows Events Test
```bash
./test_windows.sh <SIEM_IP> [PORT]
# Example:
./test_windows.sh 192.168.1.100 514
```

### AWS CloudTrail Test
```bash
./test_aws.sh <SIEM_IP> [PORT]
# Example:
./test_aws.sh 192.168.1.100 514
```

### Firewall Test (High Load)
```bash
./test_firewall.sh <SIEM_IP> [PORT]
# Example:
./test_firewall.sh 192.168.1.100 514
```

### Complete Stress Test
```bash
./test_stress.sh <SIEM_IP> [PORT]
# Example:
./test_stress.sh 192.168.1.100 514
```

## Post-Test Verification

After each test, verify in SIEM:

1. **Volume**: Number of received events matches generation
2. **Parsing**: Fields extracted correctly
3. **Timestamp**: Correct time (check timezone)
4. **Source**: Source IP identified
5. **Alerts**: Correlations working

## Manual Commands

```bash
# Quick 100 events test
python3 -m soc_log_generator generate --generator windows --eps 100 --duration 10 --syslog-host <IP>

# Test to file
python3 -m soc_log_generator generate --generator aws --output-file test.json --duration 60

# Multi-source test
python3 -m soc_log_generator generate --generator firewall --multi 5 --eps 1000 --syslog-host <IP>
```

## Troubleshooting

### Connectivity Test
```bash
# Check open port
telnet <SIEM_IP> 514

# UDP test
nc -vu <SIEM_IP> 514

# TCP test
nc -v <SIEM_IP> 514
```

### Verify Generation
```bash
# Generate to stdout (without sending to SIEM)
python3 -m soc_log_generator generate --generator windows --eps 10 --duration 5

# Count generated events
python3 -m soc_log_generator generate --generator windows --output-file test.log --duration 60
wc -l test.log
```

## Test Logbook

Fill in the `../TEST_PROCEDURE.md` file with results from each test.

## Support

In case of issues:
1. Check logs: `test_*.log`
2. Check network connectivity
3. Check SIEM configuration (port, protocol)
4. See `../TEST_PROCEDURE.md` troubleshooting section
