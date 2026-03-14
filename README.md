# Tracking the Lifetime of Malicious Indicators in Public Threat Intelligence Feeds

## Παρακολούθηση της διάρκειας ζωής κακώβουλων δεικτών σε ροές πληροφοριών για δημόσιες απειλές

## Summary

## Περίληψη

## Abstract

--

## Introduction

The Internet is a fundamental tool for communication, information sharing and business activities worldwide. However, this widespread use has led to increased cyber threats such as malware, phishing and DDoS attacks. To combat these threats, public threat intelligence feeds have been developed, such as VirusTotal, Censys, and AbuseIPDB, ThreatFox, OpenPhish and Cinsscore which collect and share malicious indicators such as IP addresses, domains and file hashes.

The importance of these tools lies in their ability to provide free access to data that helps organizations and researchers identify and mitigate threats in real time. VirusTotal, for example, allows the analysis of files and URLs through multiple antivirus engines, while Censys scans the Internet for vulnerabilities in devices and services. AbuseIPDB records reports of IP address abuse, helping the community combat spam and attacks. ThreatFox, OpenPhish and Cinsscore provide public lists of IP addresses and domains associated with malicious activity.

However, there are disadvantages: Reliance on public data can lead to false positives, while delays in feed updates can leave security gaps. Additionally, data quality varies depending on community contributions, and there are concerns about privacy and misuse of information.

The purpose of this study is to investigate the lifetime of malicious indicators in these public threat intelligence feeds, and how long someone is vulnerable using such providers. In our research we collect data from the Tlscope tool and compare the results with other vendors to figure out how earlier Tlscope detects them. This analysis will contribute to a better understanding of the effectiveness of Threat Intelligence Feeds and the improvement of cybersecurity strategies as well as the development of more effective tools similar to those of public providers.

## Related Work

-- TODO: Search for related work and add it here --

## Limitations

The present study has certain limitations. The tools we use, especially VirusTotal and Censys, do not provide completely free usage and impose the main constraint on the number of IPs we can examine each day. Additionally, some of the tools used may provide data with time delays, which distorts the results of our research.

## Methodology

### VirusTotal

VirusTotal is a free online service that analyzes files and URLs for viruses, worms, trojans and other kinds of malicious content. It aggregates results from multiple antivirus engines, website scanners and user contributions to provide comprehensive threat intelligence. VirusTotal allows users to upload files or submit URLs for analysis, and it returns detailed reports on detection results, file metadata, network activity and community comments. The service is widely used by security researchers, incident responders and organizations to identify and investigate potential threats.

In our study, we send the IP address to VirusTotal for a rescan with `GET https://www.virustotal.com/api/v3/ip_addresses/XXX.XXX.XXX.XXX/analyse` and then retrieve that analysis results with `GET https://www.virustotal.com/api/v3/analyses/id_XXX` each day to check if it is classified as malicious and record the results.

### Censys

Censys is a search engine for the Internet that scans the entire public IPv4 address space and collects data on devices, websites, certificates, and other Internet assets. It provides detailed insights into the security posture of the Internet, helping organizations understand their exposure, identify vulnerabilities, and improve their cybersecurity defenses. Censys aggregates data from various sources to offer comprehensive views of Internet infrastructure, including protocol support, software versions, and potential security weaknesses.

In our study, we check if each IP address is contained in the Censys database as a malicious address each day through the API `GET https://api.platform.censys.io/v3/global/asset/host/XXX.XXX.XXX.XXX` and record the results.

### AbuseIPDB

AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers and abusive activity on the internet. It provides a platform for users to report and track IP addresses involved in malicious activities such as hacking attempts, spamming, DDoS attacks and other forms of abuse. The database is community-driven, allowing users to submit reports of abusive IP addresses and view the history of reported incidents. AbuseIPDB serves as a valuable resource for individuals and organizations looking to protect themselves from cyber threats by providing information on potentially harmful IP addresses.

For our study, we check if each IP address is contained in the AbuseIPDB database as a malicious address each day through the API `GET https://api.abuseipdb.com/api/v2/check -d '{"ipAddress": "XXX.XXX.XXX.XXX", "maxAgeInDays": "30"}'`

### ThreatFox

ThreatFox is a free, community-driven platform from abuse.ch and Spamhaus for sharing indicators of compromise (IOCs) related to malware. It collects IP addresses, domains, URLs and file hashes associated with botnet C2 servers, malware delivery, credit card skimming and other threats. The Community API is free and provides access to recently added IOCs (within 7 days) and the ability to search and filter by malware family and threat type. Each IOC contains detailed information such as confidence level, first_seen/last_seen timestamps, reference links and tags. IOCs older than 6 months are automatically expired and no longer appear via the API, but remain visible and searchable through the web interface (flagged as expired).

In our study, we check if each IP address is contained in the ThreatFox IOCs as a C2 server or malware payload delivery each day through the API `POST https://threatfox-api.abuse.ch/api/v1/ -d '{ "query": "search_ioc", "search_term": "XXX.XXX.XXX.XXX", "exact_match": true }'` and record the results.

### Cinsscore

CINS (Collective Intelligence Network Security) is a threat monitoring system that collects attack data from a global network of Sentinel IPS devices and other trusted security sources. CINS provides a score for each IP address worldwide, which indicates the trustworthiness of the address. The purpose of CINS is to identify various categories of malicious IP addresses (scanners, C2 servers, botnet infrastructure) and provide detailed WHOIS information and scoring history. The CINS Army List is a public list of malicious IP addresses that is constantly updated and provided free for use in firewalls and IDS/IPS systems.

In our study, we download the Army List from the address `https://cinsscore.com/list/ci-badguys.txt`. We then check if each IP address is contained in the CINS Army List each day and record whether Cinsscore classifies it as malicious or harmless (benign).

### OpenPhish

OpenPhish is a threat intelligence service that specializes in detecting and tracking phishing IPs. It processes URLs daily to identify new phishing pages and provides summary information about targeted verticals (e.g., cryptocurrency 22%, Netflix 12%, Roblox 9%), business sectors (e.g., online services 25%, cryptocurrency 24%, financial 11%) and the networks hosting the pages. The Community Feed is free and updated every 12 hours, providing a simple list of phishing URLs in text format.

In our study, we first convert the hostnames from URLs at `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt` to IP addresses, then check if each IP address is contained in the OpenPhish list each day and record the results.

### Data Collection and Analysis

Each group examined consists of approximately 2400 IP addresses that have been recorded by the Tlscope tool. These addresses were selected based on their classification as malicious by Tlscope. Data collection was conducted over a period of one to two months for each group, and occurs every 3 days. Data collected mainly consists of the classification of each IP address by each provider.

Subsequently, for data analysis, all generated CSV files are read to count the necessary fields and extract IP addresses. Useful graphs include the percentage of malicious addresses per day and the increase or decrease of malicious addresses per day.

## Results

## Discussion

## Conclusion

## Future Work

## References
