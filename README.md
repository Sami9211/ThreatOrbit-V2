# ThreatOrbit Platform
**Threat Intelligence Ingestion + Log Anomaly Detection + STIX/OpenCTI Integration**

ThreatOrbit is a two-service cybersecurity platform:

- **Threat API (`threat_api`)**  
  Ingests external threat feeds (RSS, darkweb OSINT, social OSINT, OTX, abuse.ch), normalizes and trust-scores indicators, enriches with VirusTotal (optional), and exports STIX 2.1.

- **Log API (`log_api`)**  
  Parses logs (Apache, Syslog, Windows Event, Generic), detects anomalies via Pattern/Statistical/ML/Temporal engines, generates HTML reports, and exports STIX 2.1 from findings.

The project is designed for **individual analysts** or **small teams** who want deployable CTI + anomaly detection workflows.

---

## 1) System Requirements

## Minimum
- OS: Linux / macOS / Windows (WSL2 recommended on Windows)
- CPU: 2 cores
- RAM: 4 GB
- Disk: 5 GB free
- Docker + Docker Compose
- Git

## Recommended
- CPU: 4+ cores
- RAM: 8–16 GB
- Disk: 20+ GB
- Stable internet connection (for feed ingestion and external enrichment APIs)

---

## 2) Prerequisites

Before using ThreatOrbit with full CTI workflow:

1. **Deploy OpenCTI first**  
   Official OpenCTI deployment documentation:  
   **https://docs.opencti.io/latest/deployment/**

2. Ensure OpenCTI is reachable from where ThreatOrbit runs (e.g., `http://localhost:8080` or your server URL).

3. (Optional, recommended) Prepare API keys:
   - AlienVault OTX
   - VirusTotal
   - OpenCTI API token

---

## 3) Project Structure

```text
threatorbit-platform/
├── README.md
├── .gitignore
├── docker-compose.yml
├── docs/
│   ├── architecture.md
│   ├── opencti_integration.md
│   └── api_examples.md
│
├── threat_api/
│   ├── Dockerfile
│   ├── main.py
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   ├── normalization.py
│   ├── trust_scoring.py
│   ├── metrics.py
│   ├── scheduler.py
│   ├── retention.py
│   ├── source_health.py
│   ├── rate_limit.py
│   ├── opencti_push.py
│   ├── source_trust_config.json
│   ├── rss_feeds.txt
│   ├── darkweb_sources.txt
│   ├── social_sources.txt
│   ├── requirements.txt
│   ├── tests/
│   │   └── test_health.py
│   ├── fetchers/
│   │   ├── otx.py
│   │   ├── abusech.py
│   │   ├── rss.py
│   │   ├── darkweb_osint.py
│   │   └── social_osint.py
│   ├── enrichment/
│   │   └── virustotal.py
│   └── stix_converter/
│       └── converter.py
│
└── log_api/
    ├── Dockerfile
    ├── main.py
    ├── config.py
    ├── models.py
    ├── stix_from_findings.py
    ├── metrics.py
    ├── db.py
    ├── requirements.txt
    ├── tests/
    │   └── test_health.py
    ├── parsers/
    │   ├── apache.py
    │   ├── syslog.py
    │   ├── windows_event.py
    │   └── generic.py
    ├── detectors/
    │   ├── pattern.py
    │   ├── statistical.py
    │   ├── ml_detector.py
    │   └── temporal.py
    ├── alerts/
    │   └── alerter.py
    ├── reporter/
    │   └── report.py
    └── sample_logs/
        └── generator.py
```

---

## 4) Installation & Startup

## Option A (Recommended): Docker Compose

From repo root:

```bash
docker compose up --build
```

Services:
- Threat API → `http://127.0.0.1:8000`
- Log API → `http://127.0.0.1:8001`

Stop:
```bash
docker compose down
```

---

## Option B: Local Python Environments (without Docker)

Use two terminals.

### Terminal 1 (Threat API)
```bash
cd threat_api
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Terminal 2 (Log API)
```bash
cd log_api
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

---

## 5) Configuration

## Threat API config
Edit `threat_api/config.py`:

- `APP_API_KEY` (**required**)
- `OTX_API_KEY` (optional)
- `VIRUSTOTAL_API_KEY` (optional)
- `OPENCTI_URL` (if using OpenCTI workflow)
- `OPENCTI_API_KEY` (if using OpenCTI workflow)

## Feed source files
Populate with one URL per line:

- `threat_api/rss_feeds.txt`
- `threat_api/darkweb_sources.txt`
- `threat_api/social_sources.txt`

## Trust scoring
Edit:
- `threat_api/source_trust_config.json`

You can define:
- default confidence baseline
- per-source confidence weights
- per-feed overrides

---

## 6) Health Checks

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8001/health
```

Optional:
```bash
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8001/ready
```

---

## 7) Threat API Usage

> Add your API key header:
> `X-API-Key: YOUR_APP_API_KEY_HERE`

### Run ingestion
```bash
curl -X POST "http://127.0.0.1:8000/fetch?enrich=true&max_enrich=25" \
  -H "X-API-Key: YOUR_APP_API_KEY_HERE"
```

### Get IOC sample
```bash
curl "http://127.0.0.1:8000/iocs?limit=20" \
  -H "X-API-Key: YOUR_APP_API_KEY_HERE"
```

### Source health snapshot
```bash
curl "http://127.0.0.1:8000/source-health" \
  -H "X-API-Key: YOUR_APP_API_KEY_HERE"
```

### Export STIX bundle
```bash
curl -X POST "http://127.0.0.1:8000/stix/export" \
  -H "X-API-Key: YOUR_APP_API_KEY_HERE" \
  -o threat_stix_bundle.json
```

---

## 8) Log API Usage

### Analyze logs
```bash
curl -X POST "http://127.0.0.1:8001/analyse?log_format=apache&generate_report=true" \
  -F "file=@log_api/sample_logs/sample_apache.log"
```

### Open generated HTML report
- `http://127.0.0.1:8001/report`

### Severity trend summary
```bash
curl "http://127.0.0.1:8001/trends/severity"
```

### Export STIX from a result
```bash
curl "http://127.0.0.1:8001/results/<RESULT_ID>/stix" -o log_stix_bundle.json
```

---

## 9) OpenCTI Integration Workflow (End-to-End)

## Step 1: Ensure OpenCTI is running
Follow official docs:  
**https://docs.opencti.io/latest/deployment/**

## Step 2: Generate Threat STIX
```bash
curl -X POST "http://127.0.0.1:8000/stix/export" \
  -H "X-API-Key: YOUR_APP_API_KEY_HERE" \
  -o threat_stix_bundle.json
```

## Step 3: Generate Log STIX
```bash
curl "http://127.0.0.1:8001/results/<RESULT_ID>/stix" -o log_stix_bundle.json
```

## Step 4: Import both bundles into OpenCTI
In OpenCTI UI:
- Go to **Data → Import**
- Upload:
  - `threat_stix_bundle.json`
  - `log_stix_bundle.json`

This gives you both:
- external indicator intelligence
- internal telemetry-based detections

in the same CTI platform.

---

## 10) One-Command Verification Runbook (10 checks)

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
curl -X POST "http://127.0.0.1:8000/fetch?enrich=false&max_enrich=10" -H "X-API-Key: YOUR_APP_API_KEY_HERE"

# 6) Confirm threat IOCs
curl "http://127.0.0.1:8000/iocs?limit=5" -H "X-API-Key: YOUR_APP_API_KEY_HERE"

# 7) Export threat STIX
curl -X POST "http://127.0.0.1:8000/stix/export" -H "X-API-Key: YOUR_APP_API_KEY_HERE" -o threat_stix_bundle.json

# 8) Run log analysis
curl -X POST "http://127.0.0.1:8001/analyse?log_format=apache&generate_report=true" -F "file=@log_api/sample_logs/sample_apache.log"

# 9) Confirm report endpoint
curl -I http://127.0.0.1:8001/report

# 10) Run tests
sh -c "cd threat_api && pytest -q && cd ../log_api && pytest -q"
```

---

## 11) API Summary

## Threat API (`:8000`)
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `POST /fetch` *(API key)*
- `GET /iocs` *(API key)*
- `GET /source-health` *(API key)*
- `GET /source-stats` *(API key)*
- `GET /trust/config` *(API key)*
- `POST /stix/export` *(API key)*
- `POST /opencti/push` *(API key; connector placeholder behavior)*

## Log API (`:8001`)
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /trends/severity`
- `POST /analyse`
- `GET /jobs/{job_id}`
- `GET /report`
- `GET /results/{result_id}`
- `GET /results/{result_id}/stix`

---
## 12) Final Verification Checklist

# 1) Start both APIs in containers
docker compose up --build -d

# 2) Confirm containers are healthy/running
docker compose ps

# 3) Threat API health check
curl http://127.0.0.1:8000/health

# 4) Log API health check
curl http://127.0.0.1:8001/health

# 5) Threat API fetch pipeline run (replace key)
curl -X POST "http://127.0.0.1:8000/fetch?enrich=false&max_enrich=10" -H "X-API-Key: YOUR_APP_API_KEY_HERE"

# 6) Confirm Threat API has IOCs
curl "http://127.0.0.1:8000/iocs?limit=5" -H "X-API-Key: YOUR_APP_API_KEY_HERE"

# 7) Export Threat STIX bundle to file
curl -X POST "http://127.0.0.1:8000/stix/export" -H "X-API-Key: YOUR_APP_API_KEY_HERE" -o threat_stix_bundle.json

# 8) Run Log API analysis on sample Apache log
curl -X POST "http://127.0.0.1:8001/analyse?log_format=apache&generate_report=true" -F "file=@log_api/sample_logs/sample_apache.log"

# 9) Confirm report endpoint is serving HTML
curl -I http://127.0.0.1:8001/report

# 10) Run both test suites
sh -c "cd threat_api && pytest -q && cd ../log_api && pytest -q"
```


## 13) Troubleshooting

## Docker issues
- Rebuild clean:
```bash
docker compose down
docker compose up --build
```

## 401 Unauthorized (Threat API)
- Ensure header exists and matches `APP_API_KEY`:
```http
X-API-Key: YOUR_APP_API_KEY_HERE
```

## No IOCs ingested
- Feed files may be empty or URLs unreachable.
- Check `/source-health` for errors.

## STIX export returns empty/no data
- Run `/fetch` first (Threat API) or `/analyse` first (Log API).

## OpenCTI import problems
- Validate OpenCTI is running and accessible.
- Use OpenCTI UI import first before automating push.
- Confirm bundle files are valid JSON and non-empty.

## ML detector warnings
- Ensure `scikit-learn` and `numpy` are installed in `log_api`.

## Rate-limit errors
- You are sending too many requests too quickly to Threat API.
- Retry after 60 seconds or raise limit in config.

---

## 14) Roadmap (Practical next upgrades)

- PostgreSQL backend (production persistence)
- Direct OpenCTI connector upload flow
- Slack/Email alert notifications
- Analyst feedback loop for false positives
- Grafana/Prometheus monitoring dashboards
