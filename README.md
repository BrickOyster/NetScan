# Tracking the Lifetime of Malicious Indicators in Public Threat Intelligence Feeds

Παρακολούθηση της διάρκειας ζωής κακόβουλων δεικτών σε ροές πληροφοριών για δημόσιες απειλές

**[Full documentation is available in the Wiki](https://github.com/BrickOyster/NetScan/wiki)**

## Quick Start

### 1. Configure API keys

```bash
cp .env_ex .env
# Edit .env and fill in your API keys
```

See [Configuration](https://github.com/BrickOyster/NetScan/wiki/Configuration) for key format and available services.

### 2. Collect data for a group

```bash
python runfetch.py -f <group_folder>/
```

See [Data Collection](https://github.com/BrickOyster/NetScan/wiki/Data-Collection) for full CLI options and input format.

### 3. Analyse collected data

```bash
python runanalysis.py -f <group_folder>/
```

See [Analysis](https://github.com/BrickOyster/NetScan/wiki/Analysis) for output files and graph descriptions.

## Abstract

Public threat intelligence feeds are a primary resource for identifying malicious activity on the internet. This study investigates the lifetime of malicious indicators across six public feeds — VirusTotal, AbuseIPDB, Censys, ThreatFox, Cinsscore, and OpenPhish — using IP addresses classified as malicious by TLScope as ground truth. TLScope is an active TLS fingerprinting system that identifies malicious servers through machine learning without inspecting payload content. Each IP is tracked every three days across all providers for one to two months, measuring detection lag (how quickly providers identify what TLScope has already found), indicator persistence (how long a detection is maintained), and inter-provider agreement. Results quantify the gap between specialised active scanning and public feed coverage, contributing to a broader understanding of threat intelligence ecosystem effectiveness and the temporal lifecycle of malicious indicators.

## Περίληψη

Οι δημόσιες ροές πληροφοριών για απειλές αποτελούν σημαντικό εργαλείο για τον εντοπισμό κακόβουλης δραστηριότητας στο διαδίκτυο. Στην παρούσα εργασία διερευνάται η διάρκεια ζωής κακόβουλων δεικτών σε έξι δημόσιες ροές (VirusTotal, AbuseIPDB, Censys, ThreatFox, Cinsscore και OpenPhish), χρησιμοποιώντας ως δεδομένα αναφοράς διευθύνσεις IP που έχουν ταξινομηθεί ως κακόβουλες από το εργαλείο TLScope. Κάθε διεύθυνση παρακολουθείται ανά τρεις ημέρες σε κάθε πάροχο για διάστημα ενός έως δύο μηνών, με σκοπό τη μέτρηση της καθυστέρησης ανίχνευσης, της επιμονής των δεικτών και του βαθμού συμφωνίας μεταξύ των παρόχων. Τα αποτελέσματα ποσοτικοποιούν το χάσμα μεταξύ εξειδικευμένης ενεργής σάρωσης TLS και της κάλυψης από δημόσιες ροές πληροφοριών, συμβάλλοντας στην κατανόηση της αποτελεσματικότητας του οικοσυστήματος Threat Intelligence.

## Wiki Contents

| Page | Description |
| --- | --- |
| [Configuration](https://github.com/BrickOyster/NetScan/wiki/Configuration) | Environment setup, API key format, rate limits |
| [Methodology](https://github.com/BrickOyster/NetScan/wiki/Methodology) | Research design, data collection strategy, analysis metrics |
| [Vendors](https://github.com/BrickOyster/NetScan/wiki/Vendors) | Per-provider API details, thresholds, and classification logic |
| [Data Collection](https://github.com/BrickOyster/NetScan/wiki/Data-Collection) | Input format, wave structure, fetch pipeline, CLI reference |
| [Analysis](https://github.com/BrickOyster/NetScan/wiki/Analysis) | Analysis pipeline, output files, graph descriptions, statistics |
| [Related Work](https://github.com/BrickOyster/NetScan/wiki/Related-Work) | Annotated bibliography: relevance to TLScope and NetScan |
| [Results](https://github.com/BrickOyster/NetScan/wiki/Results) | Study findings: detection rates, detection lag, provider coverage |
| [Future Work](https://github.com/BrickOyster/NetScan/wiki/Future-Work) | Limitations, open questions, and directions for further research |

---

| NetScan | Tracking the Lifetime of Malicious Indicators in Public Threat Intelligence Feeds |
| --- | --- |
| Author | Dimitris Keramidas |
| Last updated | June 2026 |
