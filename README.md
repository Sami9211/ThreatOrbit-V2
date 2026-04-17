# ThreatOrbit Platform

**Threat Intelligence Ingestion + Log Anomaly Detection + STIX/OpenCTI Integration**

ThreatOrbit is a two-service cybersecurity platform:

* **Threat API (`threat\_api`)**  
Ingests external threat feeds (RSS, darkweb OSINT, social OSINT, OTX, abuse.ch), normalizes and trust-scores indicators, enriches with VirusTotal (optional), and exports STIX 2.1.
* **Log API (`log\_api`)**  
Parses logs (Apache, Syslog, Windows Event, Generic), detects anomalies via Pattern/Statistical/ML/Temporal engines, generates HTML reports, and exports STIX 2.1 from findings.

The project is designed for **individual analysts** or **small teams** who want deployable CTI + anomaly detection workflows.

\---

## 1\) System Requirements

## Minimum

* OS: Linux / macOS / Windows (WSL2 recommended on Windows)
* CPU: 2 cores
* RAM: 4 GB
* Disk: 5 GB free
* Docker + Docker Compose
* Git

## Recommended

* CPU: 4+ cores
* RAM: 8–16 GB
* Disk: 20+ GB
* Stable internet connection (for feed ingestion and external enrichment APIs)

\---

## 2\) Prerequisites

Before using ThreatOrbit with full CTI workflow:

1. **Deploy OpenCTI first**  
Official OpenCTI deployment documentation:  
**https://docs.opencti.io/latest/deployment/**
2. Ensure OpenCTI is reachable from where ThreatOrbit runs (e.g., `http://localhost:8080` or your server URL).
3. (Optional, recommended) Prepare API keys:

   * AlienVault OTX
   * VirusTotal
   * OpenCTI API token

\---

## 3\) Project Structure

```text
threatorbit-platform/
├── README.md
├── .gitignore
├── docker-compose.yml
├── docs/
│   ├── architecture.md
│   ├── opencti\_integration.md
│   └── api\_examples.md
├── threat\_api/
│   ├── main.py
│   ├── config.py
│   ├── requirements.txt
│   ├── source\_trust\_config.json
│   ├── rss\_feeds.txt
│   ├── darkweb\_sources.txt
│   ├── social\_sources.txt
│   ├── fetchers/
│   ├── enrichment/
│   └── stix\_converter/
└── log\_api/
    ├── main.py
    ├── config.py
    ├── requirements.txt
    ├── parsers/
    ├── detectors/
    ├── alerts/
    ├── reporter/
    └── sample\_logs/
```

\---

## 4\) Installation \& Startup

## Option A (Recommended): Docker Compose

From repo root:

```bash
docker compose up --build
```

Services:

* Threat API → `http://127.0.0.1:8000`
* Log API → `http://127.0.0.1:8001`

Stop:

```bash
docker compose down
```

\---

## Option B: Local Python Environments (without Docker)

Use two terminals.

### Terminal 1 (Threat API)

```bash
cd threat\_api
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Terminal 2 (Log API)

```bash
cd log\_api
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

\---

## 5\) Configuration

## Threat API config

Edit `threat\_api/config.py`:

* `APP\_API\_KEY` (**required**)
* `OTX\_API\_KEY` (optional)
* `VIRUSTOTAL\_API\_KEY` (optional)
* `OPENCTI\_URL` (if using OpenCTI workflow)
* `OPENCTI\_API\_KEY` (if using OpenCTI workflow)

## Feed source files

Populate with one URL per line:

* `threat\_api/rss\_feeds.txt`
* `threat\_api/darkweb\_sources.txt`
* `threat\_api/social\_sources.txt`

## Trust scoring

Edit:

* `threat\_api/source\_trust\_config.json`

You can define:

* default confidence baseline
* per-source confidence weights
* per-feed overrides

\---

## 6\) Health Checks

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8001/health
```

Optional:

```bash
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8001/ready
```

\---

## 7\) Threat API Usage

> Add your API key header:
> `X-API-Key: YOUR\_APP\_API\_KEY\_HERE`

### Run ingestion

```bash
curl -X POST "http://127.0.0.1:8000/fetch?enrich=true\&max\_enrich=25" \\
  -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE"
```

### Get IOC sample

```bash
curl "http://127.0.0.1:8000/iocs?limit=20" \\
  -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE"
```

### Source health snapshot

```bash
curl "http://127.0.0.1:8000/source-health" \\
  -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE"
```

### Export STIX bundle

```bash
curl -X POST "http://127.0.0.1:8000/stix/export" \\
  -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE" \\
  -o threat\_stix\_bundle.json
```

\---

## 8\) Log API Usage

### Analyze logs

```bash
curl -X POST "http://127.0.0.1:8001/analyse?log\_format=apache\&generate\_report=true" \\
  -F "file=@log\_api/sample\_logs/sample\_apache.log"
```

### Open generated HTML report

* `http://127.0.0.1:8001/report`

### Severity trend summary

```bash
curl "http://127.0.0.1:8001/trends/severity"
```

### Export STIX from a result

```bash
curl "http://127.0.0.1:8001/results/<RESULT\_ID>/stix" -o log\_stix\_bundle.json
```

\---

## 9\) OpenCTI Integration Workflow (End-to-End)

## Step 1: Ensure OpenCTI is running

Follow official docs:  
**https://docs.opencti.io/latest/deployment/**

## Step 2: Generate Threat STIX

```bash
curl -X POST "http://127.0.0.1:8000/stix/export" \\
  -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE" \\
  -o threat\_stix\_bundle.json
```

## Step 3: Generate Log STIX

```bash
curl "http://127.0.0.1:8001/results/<RESULT\_ID>/stix" -o log\_stix\_bundle.json
```

## Step 4: Import both bundles into OpenCTI

In OpenCTI UI:

* Go to **Data → Import**
* Upload:

  * `threat\_stix\_bundle.json`
  * `log\_stix\_bundle.json`

This gives you both:

* external indicator intelligence
* internal telemetry-based detections

in the same CTI platform.

\---

## 10\) One-Command Verification Runbook (10 checks)

From repo root:

```bash
# 1) Start services
docker compose up --build -d

# 2) Check service status
docker compose ps

# 3) Threat API health
curl http://127.0.0.1:8000/health

# 4) Log API health
curl http://127.0.0.1:8001/health

# 5) Run threat fetch
curl -X POST "http://127.0.0.1:8000/fetch?enrich=false\&max\_enrich=10" -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE"

# 6) Confirm threat IOCs
curl "http://127.0.0.1:8000/iocs?limit=5" -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE"

# 7) Export threat STIX
curl -X POST "http://127.0.0.1:8000/stix/export" -H "X-API-Key: YOUR\_APP\_API\_KEY\_HERE" -o threat\_stix\_bundle.json

# 8) Run log analysis
curl -X POST "http://127.0.0.1:8001/analyse?log\_format=apache\&generate\_report=true" -F "file=@log\_api/sample\_logs/sample\_apache.log"

# 9) Confirm report endpoint
curl -I http://127.0.0.1:8001/report

# 10) Run tests
sh -c "cd threat\_api \&\& pytest -q \&\& cd ../log\_api \&\& pytest -q"
```

\---

## 11\) API Summary

## Threat API (`:8000`)

* `GET /health`
* `GET /ready`
* `GET /metrics`
* `POST /fetch` *(API key)*
* `GET /iocs` *(API key)*
* `GET /source-health` *(API key)*
* `GET /source-stats` *(API key)*
* `GET /trust/config` *(API key)*
* `POST /stix/export` *(API key)*
* `POST /opencti/push` *(API key; connector placeholder behavior)*

## Log API (`:8001`)

* `GET /health`
* `GET /ready`
* `GET /metrics`
* `GET /trends/severity`
* `POST /analyse`
* `GET /jobs/{job\_id}`
* `GET /report`
* `GET /results/{result\_id}`
* `GET /results/{result\_id}/stix`

\---

## 12\) Troubleshooting

## Docker issues

* Rebuild clean:

```bash
docker compose down
docker compose up --build
```

## 401 Unauthorized (Threat API)

* Ensure header exists and matches `APP\_API\_KEY`:

```http
X-API-Key: YOUR\_APP\_API\_KEY\_HERE
```

## No IOCs ingested

* Feed files may be empty or URLs unreachable.
* Check `/source-health` for errors.

## STIX export returns empty/no data

* Run `/fetch` first (Threat API) or `/analyse` first (Log API).

## OpenCTI import problems

* Validate OpenCTI is running and accessible.
* Use OpenCTI UI import first before automating push.
* Confirm bundle files are valid JSON and non-empty.

## ML detector warnings

* Ensure `scikit-learn` and `numpy` are installed in `log\_api`.

## Rate-limit errors

* You are sending too many requests too quickly to Threat API.
* Retry after 60 seconds or raise limit in config.

\---

## 

