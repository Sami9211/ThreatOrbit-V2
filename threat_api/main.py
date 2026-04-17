from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timezone
import uuid
import json
import os
import logging

from config import (
    API_HOST, API_PORT, APP_API_KEY,
    RATE_LIMIT_PER_MINUTE, ENABLE_SCHEDULER, SCHEDULE_FETCH_CRON_MINUTES,
    OPENCTI_URL, OPENCTI_API_KEY
)
from models import EnrichedIOC
from fetchers.otx import fetch_otx_iocs
from fetchers.abusech import fetch_abusech_iocs
from fetchers.rss import fetch_rss_iocs, get_configured_rss_feeds
from fetchers.darkweb_osint import fetch_darkweb_osint_iocs, get_configured_darkweb_sources
from fetchers.social_osint import fetch_social_osint_iocs, get_configured_social_sources
from normalization import normalize_iocs, boost_confidence_by_correlation
from trust_scoring import load_trust_config, apply_trust_scoring
from enrichment.virustotal import enrich_iocs
from stix_converter.converter import convert_to_stix_bundle, save_bundle_to_file
from rate_limit import SimpleRateLimiter
from source_health import build_source_health
from opencti_push import push_stix_to_opencti
from retention import cleanup_old_iocs
from metrics import ThreatMetrics
from scheduler import IntervalScheduler
from db import init_db

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

limiter = SimpleRateLimiter(RATE_LIMIT_PER_MINUTE)
metrics = ThreatMetrics()
scheduler = None

_store = []
_last_fetch = None
_last_source_health = {}
_fetch_in_progress = False
BUNDLE_PATH = "stix_bundle.json"


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key or key != APP_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        client = request.remote_addr or "unknown"
        if not limiter.allow(client):
            return jsonify({"error": "Rate limit exceeded"}), 429

        return fn(*args, **kwargs)
    return wrapper


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "threat_api"})


@app.get("/ready")
def ready():
    return jsonify({"ready": True})


@app.get("/metrics")
def get_metrics():
    return jsonify(metrics.to_dict())


@app.get("/")
def root():
    return jsonify({
        "service": "Threat API",
        "status": "running",
        "iocs_in_memory": len(_store),
        "last_fetch": _last_fetch.isoformat() if _last_fetch else None,
        "feeds": {
            "rss": len(get_configured_rss_feeds()),
            "darkweb_osint": len(get_configured_darkweb_sources()),
            "social_osint": len(get_configured_social_sources()),
        }
    })


@app.get("/source-health")
@require_api_key
def source_health():
    return jsonify(_last_source_health or {"message": "No fetch has run yet"})


@app.get("/source-stats")
@require_api_key
def source_stats():
    counts = {}
    for i in _store:
        counts[i.source] = counts.get(i.source, 0) + 1
    return jsonify({"total_iocs": len(_store), "by_source": counts})


@app.get("/trust/config")
@require_api_key
def get_trust_config():
    return jsonify(load_trust_config())


@app.post("/fetch")
@require_api_key
def fetch():
    global _fetch_in_progress
    if _fetch_in_progress:
        return jsonify({"error": "A fetch is already in progress"}), 409

    enrich_raw = request.args.get("enrich", "true").lower()
    if enrich_raw not in ("true", "false"):
        return jsonify({"error": "enrich must be true|false"}), 400
    enrich = enrich_raw == "true"

    try:
        max_enrich = int(request.args.get("max_enrich", 50))
    except ValueError:
        return jsonify({"error": "max_enrich must be an integer"}), 400

    if max_enrich < 0 or max_enrich > 1000:
        return jsonify({"error": "max_enrich must be between 0 and 1000"}), 400

    job_id = str(uuid.uuid4())
    try:
        _run_pipeline(enrich, max_enrich)
        metrics.mark_success(len(_store))
        cleanup_old_iocs(days=30)
        return jsonify({"job_id": job_id, "status": "completed", "total_iocs": len(_store)})
    except Exception as e:
        logging.exception("Fetch failed")
        metrics.mark_failure()
        return jsonify({"job_id": job_id, "status": "failed", "error": str(e)}), 500


@app.get("/iocs")
@require_api_key
def iocs():
    ioc_type = request.args.get("ioc_type")
    source = request.args.get("source")
    threat_type = request.args.get("threat_type")
    malicious_only = request.args.get("malicious_only", "false").lower() == "true"
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    results = _store
    if ioc_type:
        results = [i for i in results if i.ioc_type == ioc_type]
    if source:
        results = [i for i in results if source.lower() in i.source.lower()]
    if threat_type:
        results = [i for i in results if i.threat_type == threat_type]
    if malicious_only:
        results = [i for i in results if (i.vt_malicious_count or 0) > 0]

    sliced = results[offset: offset + limit]
    return jsonify([i.model_dump(mode="json") for i in sliced])


@app.post("/stix/export")
@require_api_key
def export_stix():
    if not _store:
        return jsonify({"error": "No IOCs available. Run /fetch first."}), 404

    bundle = convert_to_stix_bundle(_store)
    save_bundle_to_file(bundle, BUNDLE_PATH)
    return jsonify(bundle)


@app.post("/opencti/push")
@require_api_key
def opencti_push():
    if not os.path.exists(BUNDLE_PATH):
        return jsonify({"error": "No STIX bundle found. Run /stix/export first."}), 404

    with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    result = push_stix_to_opencti(OPENCTI_URL, OPENCTI_API_KEY, bundle)
    return jsonify(result), (200 if result.get("ok") else 400)


def _run_pipeline(enrich: bool, max_enrich: int):
    global _store, _last_fetch, _last_source_health, _fetch_in_progress
    _fetch_in_progress = True
    try:
        res_otx = fetch_otx_iocs()
        res_abuse = fetch_abusech_iocs()
        res_rss = fetch_rss_iocs()
        res_dark = fetch_darkweb_osint_iocs()
        res_social = fetch_social_osint_iocs()

        all_iocs = res_otx.iocs + res_abuse.iocs + res_rss.iocs + res_dark.iocs + res_social.iocs
        normalized = normalize_iocs(all_iocs)
        trusted = apply_trust_scoring(normalized, load_trust_config())

        seen = set()
        dedup = []
        for i in trusted:
            if i.value in seen:
                continue
            seen.add(i.value)
            dedup.append(i)

        correlated = boost_confidence_by_correlation(dedup)

        for i in correlated:
            i.extra = i.extra or {}
            i.extra["confidence_explain"] = {
                "final_confidence": i.confidence,
                "tags": (i.tags or [])[:8]
            }

        if enrich:
            enriched = enrich_iocs(correlated, max_enrichments=max_enrich)
        else:
            enriched = [EnrichedIOC(**i.model_dump(), enrichment_status="skipped", enrichment_error="enrichment disabled")
                        for i in correlated]

        _store = enriched
        _last_fetch = datetime.now(timezone.utc)

        _last_source_health = build_source_health({
            "otx": {"count": len(res_otx.iocs), "errors": res_otx.errors},
            "abusech": {"count": len(res_abuse.iocs), "errors": res_abuse.errors},
            "rss": {"count": len(res_rss.iocs), "errors": res_rss.errors},
            "darkweb_osint": {"count": len(res_dark.iocs), "errors": res_dark.errors},
            "social_osint": {"count": len(res_social.iocs), "errors": res_social.errors},
        })
    finally:
        _fetch_in_progress = False


def _scheduled_fetch():
    if _fetch_in_progress:
        return
    try:
        _run_pipeline(enrich=True, max_enrich=25)
        metrics.mark_success(len(_store))
        cleanup_old_iocs(days=30)
    except Exception:
        logging.exception("Scheduled fetch failed")
        metrics.mark_failure()


if __name__ == "__main__":
    init_db()
    if ENABLE_SCHEDULER:
        scheduler = IntervalScheduler(SCHEDULE_FETCH_CRON_MINUTES * 60, _scheduled_fetch)
        scheduler.start()
    app.run(host=API_HOST, port=API_PORT, debug=True)