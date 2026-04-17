# API auth
APP_API_KEY = "YOUR_APP_API_KEY_HERE"

# Server
API_HOST = "0.0.0.0"
API_PORT = 8000

# DB
DATABASE_URL = "sqlite:///threat_api.db"

# External sources / enrichment
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"
OTX_DAYS_BACK = 14

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
VT_RATE_LIMIT_SECONDS = 15

ABUSECH_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
ABUSECH_MALWARE_URL = "https://mb-api.abuse.ch/api/v1/"
ABUSECH_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# STIX
STIX_IDENTITY_NAME = "ThreatOrbit CTI Platform"
STIX_IDENTITY_CLASS = "organization"

# OpenCTI
OPENCTI_URL = "http://localhost:8080"
OPENCTI_API_KEY = "YOUR_OPENCTI_API_KEY_HERE"

# Scheduler
ENABLE_SCHEDULER = True
SCHEDULE_FETCH_CRON_MINUTES = 60

# Rate limiting
RATE_LIMIT_PER_MINUTE = 120