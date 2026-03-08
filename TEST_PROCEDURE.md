# Procédure de Test sur SIEM - Cahier de Test

> **Document à remplir manuellement lors des tests sur SIEM réels**

---

## 1. Préparation du Test

### 1.1 Environnement de Test

```
Date: _______________
Testeur: _______________
SIEM Cible: □ LogPoint □ Splunk □ Elastic □ QRadar □ Autre: _______
Version SIEM: _______________
Environnement: □ Prod □ Staging □ Lab
```

### 1.2 Collecteur/Forwarder

```
Type de collecteur: □ Syslog UDP □ Syslog TCP □ Agent □ API □ S3
IP Collecteur: _______________
Port: _______________
Protocole: □ UDP □ TCP □ TLS
```

---

## 2. Commandes de Test par Source

### 2.1 Windows Events → SIEM

**Génération vers Syslog:**
```bash
# Test basique - 100 EPS pendant 60 secondes
python3 -m soc_log_generator generate \
  --generator windows \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-protocol tcp \
  --eps 100 \
  --duration 60 \
  --syslog-format syslog
```

**Options:**
- `--eps 100` : Events par seconde (ajuster selon capacité SIEM)
- `--duration 60` : Durée en secondes (0 = illimité)
- `--syslog-format syslog` : Format syslog natif
- `--syslog-format json` : Format JSON
- `--syslog-format cef` : Format CEF (pour ArcSight/QRadar)

**À vérifier dans le SIEM:**
```
□ Events reçus: _______
□ Parsing correct: □ Oui □ Non
□ Champs extraits: _______________
□ Timestamp correct: □ Oui □ Non
□ Source IP identifiée: □ Oui □ Non
□ Severité mapping correct: □ Oui □ Non
```

---

### 2.2 Linux Auth → SIEM

**Génération:**
```bash
# Format syslog standard
python3 -m soc_log_generator generate \
  --generator linux \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --eps 50 \
  --duration 120
```

**Scénario spécifique (brute force SSH):**
```bash
# Générer beaucoup d'échecs SSH
python3 -m soc_log_generator generate \
  --generator linux \
  --mode burst \
  --start-eps 10 \
  --eps 500 \
  --ramp-time 30 \
  --duration 60
```

**À vérifier:**
```
□ Events reçus: _______
□ Username extrait: □ Oui □ Non
□ IP source extraite: □ Oui □ Non
□ Type d'authentification: □ Oui □ Non
□ Alerte déclenchée: □ Oui □ Non (laquelle: _______)
```

---

### 2.3 Firewall (Palo Alto) → SIEM

**Génération CEF (recommandé pour ArcSight/QRadar):**
```bash
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format cef \
  --eps 1000 \
  --duration 300
```

**Génération JSON (pour Splunk/Elastic):**
```bash
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 1000 \
  --duration 300
```

**À vérifier:**
```
□ App ID identifié: □ Oui □ Non
□ Zones (src/dst): □ Oui □ Non
□ Action (allow/deny): □ Oui □ Non
□ Bytes/packets comptés: □ Oui □ Non
□ Session ID tracking: □ Oui □ Non
□ Catégorisation URL: □ Oui □ Non
```

---

### 2.4 AWS CloudTrail → SIEM

**Options d'ingestion:**

**A. Via Syslog (direct):**
```bash
python3 -m soc_log_generator generate \
  --generator aws \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 600
```

**B. Vers fichier (pour ingestion S3/simulation):**
```bash
# Générer fichier pour ingestion S3
python3 -m soc_log_generator generate \
  --generator aws \
  --output-file /tmp/aws_cloudtrail_test.json \
  --eps 100 \
  --duration 300

# Compresser comme CloudTrail réel
gzip /tmp/aws_cloudtrail_test.json
# Uploader vers bucket S3 de test
aws s3 cp /tmp/aws_cloudtrail_test.json.gz s3://bucket-test/AWSLogs/123456789012/
```

**C. Multi-compte (simulation):**
```bash
# Générer avec plusieurs clients parallèles
python3 -m soc_log_generator generate \
  --generator aws \
  --syslog-host <IP_SIEM> \
  --multi 5 \
  --eps 20 \
  --duration 300
```

**À vérifier:**
```
□ EventName parsé: □ Oui □ Non
□ userIdentity reconnu: □ Oui □ Non
□ awsRegion identifiée: □ Oui □ Non
□ sourceIPAddress: □ Oui □ Non
□ errorCode (si erreur): □ Oui □ Non
□ requestParameters: □ Oui □ Non
□ Dashboard AWS CloudTrail: □ Oui □ Non
```

---

### 2.5 Azure Activity → SIEM

**Via Syslog:**
```bash
python3 -m soc_log_generator generate \
  --generator azure \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 100 \
  --duration 300
```

**Test spécifique Alertes:**
```bash
# Générer des alertes de sécurité
python3 -m soc_log_generator generate \
  --generator azure \
  --mode burst \
  --start-eps 10 \
  --eps 200 \
  --duration 60
```

**À vérifier:**
```
□ Subscription ID: □ Oui □ Non
□ Resource Group: □ Oui □ Non
□ Operation Name: □ Oui □ Non
□ Caller/User: □ Oui □ Non
□ Activity Status: □ Oui □ Non
□ Category (Administrative/Security): □ Oui □ Non
```

---

### 2.6 Azure AD Sign-in → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator azure-signin \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 300
```

**À vérifier:**
```
□ UserPrincipalName: □ Oui □ Non
□ AppDisplayName: □ Oui □ Non
□ IP Address: □ Oui □ Non
□ Location (geo): □ Oui □ Non
□ Risk Level: □ Oui □ Non
□ Conditional Access Status: □ Oui □ Non
□ MFA Details: □ Oui □ Non
```

---

### 2.7 Office 365 → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator o365 \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 200 \
  --duration 300
```

**À vérifier:**
```
□ Workload (Exchange/SharePoint/Teams): □ Oui □ Non
□ Operation: □ Oui □ Non
□ UserId: □ Oui □ Non
□ ClientIP: □ Oui □ Non
□ Item/Subject (si email): □ Oui □ Non
□ SiteUrl (si SharePoint): □ Oui □ Non
```

---

### 2.8 GCP Audit → SIEM

```bash
python3 -m soc_log_generator generate \
  --generator gcp \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format json \
  --eps 50 \
  --duration 300
```

**À vérifier:**
```
□ protoPayload.methodName: □ Oui □ Non
□ protoPayload.authenticationInfo: □ Oui □ Non
□ resource.labels.project_id: □ Oui □ Non
□ severity: □ Oui □ Non
□ logName: □ Oui □ Non
```

---

## 3. Tests de Charge

### 3.1 Test de Volume Soutenu

**Objectif:** Vérifier que le SIEM tient la charge

```bash
# 1000 EPS pendant 1 heure
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --eps 1000 \
  --duration 3600
```

**Métriques à mesurer:**
```
Heure début: _______
Heure fin: _______
Events reçus (SIEM): _______
Events générés: 3,600,000
Taux de perte: _______%
CPU SIEM (moyenne): _______%
CPU SIEM (pic): _______%
Mémoire SIEM: _______
Latence ingestion (moyenne): _______ms
Latence ingestion (p99): _______ms
```

---

### 3.2 Test de Burst (Pic de charge)

**Objectif:** Tester la réaction aux pics

```bash
# Ramp up vers 5000 EPS
python3 -m soc_log_generator generate \
  --generator firewall \
  --mode ramp \
  --start-eps 100 \
  --eps 5000 \
  --ramp-time 300 \
  --duration 600
```

**Observations:**
```
□ File d'attente SIEM: □ Stable □ Augmente □ Déborde
□ Events dropped: _______
□ Latence durant burst: _______
□ Recovery time: _______
```

---

## 4. Validation des Alertes

### 4.1 Test de Corrélation

**Scénario Brute Force:**
```bash
# Terminal 1 - Générer connexions SSH normales
python3 -m soc_log_generator generate \
  --generator linux \
  --eps 5 \
  --duration 300

# Terminal 2 - Après 2 min, ajouter brute force
python3 -m soc_log_generator generate \
  --generator linux \
  --mode burst \
  --start-eps 10 \
  --eps 100 \
  --ramp-time 10 \
  --duration 60
```

**Validation:**
```
□ Alerte "Multiple Failed Logins" déclenchée: □ Oui □ Non
□ Temps de détection: _______ secondes
□ Faux positifs: _______
□ Vrais positifs: _______
```

---

### 4.2 Test de Détection Anomalie

```bash
# Générer trafic normal
python3 -m soc_log_generator generate \
  --generator firewall \
  --eps 100 \
  --duration 300

# Générer exfiltration de données (burst sortant)
python3 -m soc_log_generator generate \
  --generator firewall \
  --mode burst \
  --start-eps 100 \
  --eps 2000 \
  --duration 60
```

**Validation:**
```
□ Détection volume anormal: □ Oui □ Non
□ Détection nouvelle destination: □ Oui □ Non
□ Alerte Data Exfiltration: □ Oui □ Non
```

---

## 5. Format CEF/LEEF

### 5.1 Test CEF (ArcSight/QRadar)

```bash
# Générer format CEF
python3 -m soc_log_generator generate \
  --generator firewall \
  --syslog-host <IP_SIEM> \
  --syslog-port 514 \
  --syslog-format cef \
  --eps 100 \
  --duration 60

# Ou vers fichier pour inspection
python3 -m soc_log_generator generate \
  --generator firewall \
  --output-file /tmp/cef_test.log \
  --eps 10 \
  --duration 10

tail -5 /tmp/cef_test.log
```

**Validation CEF:**
```
□ Header CEF correct: □ Oui □ Non
□ Device Vendor/Product: □ Oui □ Non
□ Severity mapping: □ Oui □ Non
□ Extensions parsées: □ Oui □ Non (lesquelles: _______)
```

---

## 6. Résultats Globaux

### 6.1 Synthèse

| Source | Events | Reçus | % Reçu | Parsing | Alertes | Status |
|--------|--------|-------|--------|---------|---------|--------|
| Windows | | | | | | □ OK □ KO |
| Linux | | | | | | □ OK □ KO |
| Firewall | | | | | | □ OK □ KO |
| AWS | | | | | | □ OK □ KO |
| Azure | | | | | | □ OK □ KO |
| O365 | | | | | | □ OK □ KO |
| GCP | | | | | | □ OK □ KO |

### 6.2 Problèmes Identifiés

```
1. ___________________________________________________________

2. ___________________________________________________________

3. ___________________________________________________________
```

### 6.3 Corrections Apportées

```
1. ___________________________________________________________

2. ___________________________________________________________

3. ___________________________________________________________
```

### 6.4 Validation Finale

```
□ Tous les parsers fonctionnent: □ Oui □ Non
□ Pas de perte d'events < 1%: □ Oui □ Non
□ Alertes déclenchées correctement: □ Oui □ Non
□ Dashboards populates: □ Oui □ Non
□ Ready for production: □ Oui □ Non
```

---

## 7. Signatures

```
Testeur SIEM: _______________ Date: _______ Signature: _______
Testeur LogGen: _______________ Date: _______ Signature: _______
Responsable: _______________ Date: _______ Signature: _______
```

---

## Annexes

### A. Commandes Rapides

```bash
# Test rapide 100 events
python3 -m soc_log_generator generate --generator <TYPE> --eps 100 --duration 10

# Test vers fichier
python3 -m soc_log_generator generate --generator <TYPE> --output-file test.log --duration 60

# Test multi-générateurs
python3 -m soc_log_generator generate --generator windows --eps 50 &
python3 -m soc_log_generator generate --generator linux --eps 50 &
wait
```

### B. Options CLI Complètes

```
--generator {windows,linux,nxlog,firewall,proxy,dns,ids,aws,azure,o365,gcp}
--syslog-host HOST          IP ou hostname du SIEM
--syslog-port PORT          Port (défaut: 514)
--syslog-protocol {tcp,udp} Protocole
--syslog-format {syslog,json,cef} Format de sortie
--eps FLOAT                 Events par seconde
--duration INT              Durée en secondes (0 = infini)
--mode {constant,ramp,burst} Mode de génération
--multi INT                 Nombre de clients parallèles
--output-file PATH          Fichier de sortie (optionnel)
```

### C. Contact Support

```
En cas de problème:
- Logs du générateur: /tmp/soc_log_generator.log
- Vérifier connectivité: telnet <IP_SIEM> <PORT>
- Vérifier firewall: nc -zv <IP_SIEM> <PORT>
```
