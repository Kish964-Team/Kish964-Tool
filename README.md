<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&pause=1000&color=00FF41&center=true&vCenter=true&width=800&lines=Kish964+v3.0;Advanced+Origin+IP+Discovery+Framework;Unmask+Hidden+Infrastructure+Behind+Any+WAF" alt="Typing SVG" />

<br/>

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-3.0.0-ef4444?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained-Yes-16a34a?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-6366f1?style=for-the-badge)
![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-f59e0b?style=for-the-badge)

<br/>

> **"Unmasking hidden infrastructure behind the WAF edge."**
>
> A zero-config, multi-vector OSINT and active-analysis framework to discover the **real origin IP** of any WAF-protected website — built for security researchers, bug bounty hunters, and red teamers.

<br/>

[![Star this repo](https://img.shields.io/github/stars/Kish964-Team/Kish964-Tool?style=social)](https://github.com/Kish964-Team/Kish964-Tool)
[![Fork this repo](https://img.shields.io/github/forks/Kish964-Team/Kish964-Tool?style=social)](https://github.com/Kish964-Team/Kish964-Tool/fork)

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [What Makes Kish964 Different](#-what-makes-kish964-different)
- [Feature Breakdown](#-feature-breakdown)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Basic Scan](#basic-fast-scan)
  - [Full Deep Scan](#full-deep-scan)
  - [Zone Transfer + ASN](#zone-transfer--asn-enrichment)
  - [All CLI Flags](#all-cli-flags)
- [Output Formats](#-output-formats)
- [Example Output](#-example-output)
- [Configuration File](#-configuration-file)
- [Supported WAF & Cloud Providers](#-supported-waf--cloud-providers)
- [OSINT Sources](#-osint-sources)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [Disclaimer](#%EF%B8%8F-legal-disclaimer)

---

## 🌐 Overview

Modern websites hide their real servers behind **Web Application Firewalls (WAFs)** like Cloudflare, Akamai, Fastly, and Incapsula. These CDNs act as a shield — intercepting all traffic and masking the origin server's true IP address.

**Kish964 v3.0** is designed to cut through that shield using a layered, multi-vector approach:

| Layer | Technique |
|-------|-----------|
| 🔎 **Passive OSINT** | crt.sh, HackerTarget, URLScan, OTX, BufferOver |
| 🧬 **DNS Analysis** | Async A/AAAA/MX/TXT/NS brute-force with wildcard filtering |
| 🔐 **TLS Inspection** | Direct IP:443 certificate CN/SAN extraction |
| 🌐 **HTTP Probing** | Host-header injection with confidence scoring |
| 📧 **Mail Leaks** | SPF record flattening and recursive include: resolution |
| 🗺️ **Zone Transfers** | AXFR attempts against all discovered nameservers |
| 📊 **IP Enrichment** | ASN, GeoIP, PTR/Reverse DNS via ip-api.com |

---

## 🚀 What Makes Kish964 Different

Most tools stop at DNS lookups and certificate logs. Kish964 goes further:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kish964 v3.0 Pipeline                       │
│                                                                  │
│  [OSINT] ──► [DNS Brute-Force] ──► [WAF/Cloud Classification]  │
│      │                                         │                 │
│      ▼                                         ▼                 │
│  [Zone Transfer]              [HTTP Origin Verification]         │
│      │                                         │                 │
│      ▼                                         ▼                 │
│  [SSL Cert Grab]  ──────►  [ASN / PTR Enrichment]               │
│                                         │                        │
│                                         ▼                        │
│                          [Confidence-Scored Rich Report]         │
└─────────────────────────────────────────────────────────────────┘
```

Unlike a typical subdomain scanner, every discovered IP is **verified** and **enriched** before being reported — so you get zero noise and maximum signal.

---

## 🔥 Feature Breakdown

### 🌐 HTTP Origin Verifier (`--verify-http`)
The crown jewel of v3.0. Rather than blindly reporting IPs, Kish964 **proves** an IP is the real origin:

1. Fetches the canonical site response through the CDN to build a baseline (page title + content hash)
2. Directly probes each candidate IP on ports `443`, `80`, `8443`, `8080` with the `Host: target.com` header
3. Compares the direct response against the baseline using title Jaccard similarity + content fingerprinting
4. Returns a **0–100% confidence score** for each IP

```
[HTTP] 198.51.100.42 → ✓ HTTP verified (confidence: 92%) | title: "Dashboard – Acme Corp"
```

---

### 🔐 Direct IP SSL Certificate Grabber (`--grab-ssl`)
Bypasses CDN completely by connecting directly to `IP:443` over raw TCP/TLS (no DNS, no proxy):

- Extracts **Common Name (CN)** and all **Subject Alternative Names (SANs)**
- Reveals hidden backend hostnames, admin panels, and internal subdomains
- Often exposes staging environments, CI/CD servers, and internal tooling

```
[SSL] 198.51.100.42 → admin.internal.acme.com, staging.acme.com, ci.acme.com
```

---

### 🗺️ AXFR Zone Transfer (`--axfr`)
Automatically queries all NS servers and attempts a full **DNS zone transfer**:

- Builds a minimal RFC-5936 compliant AXFR TCP query
- Extracts all hostname records from the response
- Silently skips servers that refuse (the expected default)
- Flags successful transfers in bold red — a critical misconfiguration finding

```
[AXFR] Zone transfer SUCCESS on ns1.example.com! 147 records
```

---

### ⚡ Wildcard DNS Detection & Filtering (`--wildcard-check`)
Before brute-forcing, Kish964 probes a random 18-character subdomain:

- If it resolves, wildcard DNS is active — those IPs are added to a **filter list**
- All subsequent DNS results matching wildcard IPs are **automatically discarded**
- Eliminates the false positives that plague other subdomain scanners

```
[WILDCARD] example.com has wildcard DNS → 104.21.3.74 (filtered from results)
```

---

### ☁️ WAF & Cloud Provider Detection
Kish964 distinguishes between **WAF/CDN IPs** (filtered out as noise) and **cloud provider IPs** (kept as origin candidates):

| Type | Treatment | Providers |
|------|-----------|-----------|
| **WAF / CDN** | Filtered — not origin | Cloudflare, Akamai, Fastly, Incapsula |
| **Cloud** | Labeled — kept as candidate | AWS, GCP, Azure, DigitalOcean, Hetzner |

CIDR ranges are **fetched live** at scan start (with static fallbacks if offline).

---

### 📊 ASN & GeoIP Enrichment (`--asn-lookup`)
Every discovered origin IP is enriched via **ip-api.com** (no API key required):

- 🏢 Organization name
- 🔢 ASN number (e.g. `AS14618 Amazon.com, Inc.`)
- 🌍 Country code
- 🏙️ City
- 🔄 PTR / Reverse DNS record (automatic for all origin IPs)

---

### 🔍 Multi-Source OSINT (`--historical`)
Aggregates passive intelligence from **5 sources simultaneously**:

| Source | Data Type |
|--------|-----------|
| **crt.sh** | SSL certificate transparency subdomains |
| **HackerTarget** | Historical DNS host records |
| **URLScan.io** | Crawl records with associated IPs |
| **AlienVault OTX** | Passive DNS threat intelligence |
| **BufferOver.run** | Forward/reverse DNS datasets |

All discovered subdomains are automatically merged into the DNS brute-force queue.

---

### 📧 SPF Record Flattening & Mail Leak Detection
Recursively resolves SPF `include:` chains up to **5 levels deep**:

- Extracts every `ip4:`, `ip6:`, `a:`, and `include:` directive
- Classifies each IP against WAF/cloud ranges
- Flags non-WAF IPs as **"POTENTIAL ORIGIN ⭐"** — mail servers frequently expose the real hosting subnet

---

## 🏗️ Architecture

```
kish964.py
│
├── CIDRManager          # WAF + cloud CIDR fetching & classification
├── DNSResolver          # Async A/AAAA/MX/TXT/NS + wildcard detect + AXFR
├── OSINTFetcher         # crt.sh / HackerTarget / URLScan / OTX / BufferOver
├── HTTPVerifier         # Host-header probing + confidence scoring
├── SSLCertGrabber       # Direct IP:443 TLS certificate extraction
├── ASNEnricher          # Batch ip-api.com ASN/GeoIP enrichment
├── SPFFlatener          # Recursive SPF include: resolution
├── MailLeakDetector     # MX + SPF origin leak analysis
├── FaviconAnalyzer      # MurmurHash3 Shodan dork generation
├── ReportGenerator      # JSON / CSV / text export
└── Kish964              # Main orchestrator + Rich terminal output
```

---

## ⚙️ Installation

### Prerequisites
- Python **3.9** or higher
- `pip` package manager

> **Note:** To avoid dependency conflicts, it is highly recommended (and often required by modern OS environments) to install Kish964 inside an isolated Python Virtual Environment (`venv`).

### Steps

**1. Clone the repository and enter the directory**
```bash
git clone https://github.com/Kish964-Team/Kish964-Tool.git
cd Kish964-Tool

```

**2. Set up the Virtual Environment & Install Dependencies**

🐧 **For Linux / macOS (Terminal):**

```bash
# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

```

🪟 **For Windows (PowerShell):**

```powershell
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\Activate.ps1

# Install required packages
pip install -r requirements.txt

```

> **Tip:** When you are finished using the tool, you can exit the virtual environment by simply typing `deactivate` in your terminal or PowerShell.

### `requirements.txt`

```text
aiohttp>=3.9.0
aiodns>=3.1.0
rich>=13.7.0
pyfiglet>=1.0.2
mmh3>=4.0.1
tomli>=2.0.1  ; python_version < "3.11"

```

---

## 🖥️ Usage

### Basic Fast Scan
Run a quick subdomain-based origin discovery with no extra flags:

```bash
python tools.py target.com
```

> Performs async DNS resolution on the default wordlist, WAF/cloud detection, wildcard filtering, and prints a Rich summary table.

---

### Full Deep Scan
Pull out all the stops — combine wordlist brute-force with HTTP verification and direct SSL cert grabbing:

```bash
python tools.py target.com -w kish_massive_wordlist.txt --grab-ssl --verify-http
```

> For each discovered origin IP: probes it directly with `Host:` headers, scores confidence 0–100%, and extracts TLS certificate SANs to reveal hidden backends.

---

### Zone Transfer + ASN Enrichment
Attempt zone transfers on all NS servers and enrich every origin IP with ASN/GeoIP data:

```bash
python tools.py target.com --axfr --asn-lookup
```

> Zone transfer successes are highlighted in bold red and written to the report. Each origin IP is tagged with its organization, ASN, country, city, and PTR record.

---

### All CLI Flags

```
usage: kish964 [-h] [-w FILE] [-t THREADS] [-o FILE] [-f {normal,json,csv}]
               [-v] [-q] [--historical] [--shodan-key KEY]
               [--censys-id ID] [--censys-secret SECRET]
               [--verify-http] [--check-favicon] [--axfr]
               [--wildcard-check | --no-wildcard-check]
               [--grab-ssl] [--asn-lookup] [--nameservers NS [NS ...]]
               domain
```

| Flag | Description |
|------|-------------|
| `domain` | **Required.** Target domain (e.g. `example.com`) |
| `-w FILE` | Subdomain wordlist file (repeatable: `-w list1.txt -w list2.txt`) |
| `-t THREADS` | Max concurrent DNS slots (default: `100`) |
| `-o FILE` | Write report to a file |
| `-f FORMAT` | Output format: `normal`, `json`, or `csv` (default: `normal`) |
| `-v` | Verbose — also show WAF-protected and NXDOMAIN results |
| `-q` | Quiet — suppress all output except origin IPs |
| **OSINT & Passive** | |
| `--historical` | Fetch crt.sh, HackerTarget, URLScan.io, OTX, BufferOver.run |
| `--shodan-key KEY` | Shodan API key for SSL certificate reverse search |
| `--censys-id ID` | Censys API ID |
| `--censys-secret SEC` | Censys API secret |
| **Active Analysis** | |
| `--verify-http` | HTTP-probe IPs with `Host:` header + confidence score |
| `--check-favicon` | Hash favicon with MurmurHash3 and generate Shodan dork |
| `--axfr` | Attempt DNS zone transfers (AXFR) against all NS servers |
| `--wildcard-check` | Detect and filter wildcard DNS (default: **on**) |
| `--no-wildcard-check` | Disable wildcard detection |
| `--grab-ssl` | Pull TLS certificate CN/SANs directly from origin IPs |
| **Enrichment** | |
| `--asn-lookup` | Enrich origin IPs with ASN, GeoIP, and PTR records |
| `--nameservers NS` | Custom DNS resolvers (e.g. `--nameservers 8.8.8.8 1.1.1.1`) |

---

## 📁 Output Formats

### Rich Terminal Table (default)

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃              Scan Summary – target.com                             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ✅  Origin IPs found            │  4                               │
│ 🔍  HTTP-verified origin IPs    │  3                               │
│ 🛡️  WAF-protected               │  91                              │
│ ❌  Not found (NXDOMAIN)        │  4832                            │
│ 📧  Mail leaks                  │  2                               │
│ 🔍  OSINT entries               │  214                             │
│ ⏱️  Scan duration               │  38.4s                           │
└─────────────────────────────────┴──────────────────────────────────┘
```

### JSON Export (`-f json -o report.json`)

```json
{
  "target": "example.com",
  "scan_date": "2025-03-08T12:00:00Z",
  "scan_duration_s": 38.4,
  "summary": { "found_origin": 4, "verified_origin": 3 },
  "dns_results": {
    "found_origin": [
      {
        "domain": "mail.example.com",
        "ipv4": ["198.51.100.42"],
        "ip_meta": {
          "198.51.100.42": {
            "http_verified": true,
            "confidence": 92,
            "asn": "AS14618",
            "org": "Amazon.com Inc.",
            "country": "US",
            "ptr": "ec2-198-51-100-42.compute-1.amazonaws.com",
            "ssl_cns": ["admin.internal.example.com"]
          }
        }
      }
    ]
  }
}
```

### CSV Export (`-f csv -o results.csv`)

Exports all fields in a flat spreadsheet: `domain`, `status`, `origin_ips`, `verified_origin`, `waf_ips`, `cloud_ips`, `ASN`, `org`, `country`, `confidence`, and more.

---

## 🔧 Configuration File

Create `~/.kish964.toml` to persist your preferred defaults:

```toml
# ~/.kish964.toml

threads       = 200
format        = "json"
historical    = true
wildcard_check = true
asn_lookup    = true
grab_ssl      = true
nameservers   = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

shodan_key    = "YOUR_SHODAN_API_KEY"
censys_id     = "YOUR_CENSYS_ID"
censys_secret = "YOUR_CENSYS_SECRET"
```

CLI flags always **override** config file values.

---

## 🛡️ Supported WAF & Cloud Providers

| Provider | Type | CIDR Source |
|----------|------|-------------|
| **Cloudflare** | WAF/CDN | Live fetch from `cloudflare.com/ips-v4` |
| **Akamai** | WAF/CDN | Static (no public machine-readable list) |
| **Fastly** | WAF/CDN | Live fetch from `api.fastly.com/public-ip-list` |
| **Incapsula / Imperva** | WAF/CDN | Static |
| **AWS CloudFront** | Cloud | Live fetch from `ip-ranges.amazonaws.com` |
| **Google Cloud (GCP)** | Cloud | Static |
| **Microsoft Azure** | Cloud | Static |
| **DigitalOcean** | Cloud | Static |
| **Hetzner** | Cloud | Static |

> **WAF IPs** are filtered from origin candidates. **Cloud IPs** are labeled but kept — a cloud IP is still a legitimate origin.

---

## 🔍 OSINT Sources

| Source | Data | Rate Limit | API Key? |
|--------|------|-----------|----------|
| **crt.sh** | SSL certificate transparency logs | Generous | ❌ Free |
| **HackerTarget** | Historical DNS host data | 100 req/day free | ❌ Free |
| **URLScan.io** | Web crawl records + IPs | 60 req/min free | ❌ Free |
| **AlienVault OTX** | Passive DNS threat intel | Generous | ❌ Free |
| **BufferOver.run** | Forward/reverse DNS datasets | Generous | ❌ Free |
| **Shodan** | SSL cert reverse search | Paid | ✅ Required |
| **Censys** | TLS cert host matching | Free tier | ✅ Required |

---

## 📦 Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| `aiohttp` | ≥ 3.9.0 | Async HTTP client |
| `aiodns` | ≥ 3.1.0 | Async DNS resolver (pycares backend) |
| `rich` | ≥ 13.7.0 | Beautiful terminal tables and progress bars |
| `pyfiglet` | ≥ 1.0.2 | ASCII banner rendering |
| `mmh3` | ≥ 4.0.1 | MurmurHash3 for Shodan favicon dorks |
| `tomli` | ≥ 2.0.1 | Config file parsing (Python < 3.11) |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. **Fork** the repository
2. Create your feature branch: `git checkout -b feature/my-new-vector`
3. Commit your changes: `git commit -m 'Add: new OSINT source'`
4. Push to the branch: `git push origin feature/my-new-vector`
5. Open a **Pull Request**

Please follow PEP 8, include docstrings on new classes/methods, and add a brief description of your changes in the PR.

---

## 🛠️ Roadmap

- [ ] Autonomous recursive SPF IP probing
- [ ] Censys bulk IP scan integration
- [ ] Nuclei template generation from discovered origin IPs
- [ ] Docker image for zero-dependency deployment
- [ ] Web UI dashboard (Flask/FastAPI)
- [ ] Slack / Discord webhook notifications

---

<div align="center">

## ⚖️ Legal Disclaimer

</div>

> [!CAUTION]
> **This tool is intended strictly for educational purposes and authorized security testing only.**
>
> By downloading, installing, or using Kish964, you agree that:
>
> - ✅ You have **explicit written permission** from the system owner before scanning any target
> - ✅ You are conducting testing within the scope of a legitimate **bug bounty program** (e.g. HackerOne, Bugcrowd) or an authorized penetration test
> - ✅ You will comply with all applicable local, national, and international **laws and regulations**
> - ❌ You will **NOT** use this tool against systems you do not own or do not have authorized access to
> - ❌ You will **NOT** use this tool for any malicious, illegal, or unauthorized activity
>
> The **Kish964 Team** assumes **no liability** and is **not responsible** for any misuse, damage, or legal consequences arising from the use of this software. Unauthorized use of this tool may violate the **Computer Fraud and Abuse Act (CFAA)**, the **EU Directive on Attacks Against Information Systems**, and equivalent laws in your jurisdiction.
>
> **Use responsibly. Hack ethically. Get permission first.**

---

<div align="center">

Built with ❤️ by the **[Kish964 Team](https://github.com/Kish964-Team)**

⭐ **Star this repo** if Kish964 helped your research!

![Footer](https://capsule-render.vercel.app/api?type=waving&color=00FF41&height=80&section=footer)

</div>
