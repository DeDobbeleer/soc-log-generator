# Scripts de Test SIEM

## Prérequis

```bash
# Rendre les scripts exécutables
chmod +x test_*.sh

# Vérifier que le générateur est installé
python3 -m soc_log_generator --version
```

## Utilisation

### Test Windows Events
```bash
./test_windows.sh <IP_SIEM> [PORT]
# Exemple:
./test_windows.sh 192.168.1.100 514
```

### Test AWS CloudTrail
```bash
./test_aws.sh <IP_SIEM> [PORT]
# Exemple:
./test_aws.sh 192.168.1.100 514
```

### Test Firewall (Charge)
```bash
./test_firewall.sh <IP_SIEM> [PORT]
# Exemple:
./test_firewall.sh 192.168.1.100 514
```

### Test de Stress Complet
```bash
./test_stress.sh <IP_SIEM> [PORT]
# Exemple:
./test_stress.sh 192.168.1.100 514
```

## Vérification Post-Test

Après chaque test, vérifier dans le SIEM:

1. **Volume**: Nombre d'events reçus correspond à la génération
2. **Parsing**: Champs extraits correctement
3. **Timestamp**: Heure correcte (vérifier timezone)
4. **Source**: IP source identifiée
5. **Alertes**: Corrélations fonctionnent

## Commandes Manuelles

```bash
# Test rapide 100 events
python3 -m soc_log_generator generate --generator windows --eps 100 --duration 10 --syslog-host <IP>

# Test vers fichier
python3 -m soc_log_generator generate --generator aws --output-file test.json --duration 60

# Test multi-sources
python3 -m soc_log_generator generate --generator firewall --multi 5 --eps 1000 --syslog-host <IP>
```

## Dépannage

### Test de connectivité
```bash
# Vérifier port ouvert
telnet <IP_SIEM> 514

# Test UDP
nc -vu <IP_SIEM> 514

# Test TCP
nc -v <IP_SIEM> 514
```

### Vérifier génération
```bash
# Générer vers stdout (sans envoyer au SIEM)
python3 -m soc_log_generator generate --generator windows --eps 10 --duration 5

# Compter events générés
python3 -m soc_log_generator generate --generator windows --output-file test.log --duration 60
wc -l test.log
```

## Cahier de Test

Remplir le fichier `../TEST_PROCEDURE.md` avec les résultats de chaque test.

## Support

En cas de problème:
1. Vérifier logs: `test_*.log`
2. Vérifier connectivité réseau
3. Vérifier configuration SIEM (port, protocole)
4. Consulter `../TEST_PROCEDURE.md` section dépannage
