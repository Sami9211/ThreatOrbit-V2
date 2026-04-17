from datetime import datetime, timezone


def build_source_health(results: dict) -> dict:
    out = {"checked_at": datetime.now(timezone.utc).isoformat(), "sources": {}}
    for name, r in results.items():
        errs = r.get("errors", [])
        out["sources"][name] = {
            "status": "degraded" if errs else "healthy",
            "ioc_count": r.get("count", 0),
            "error_count": len(errs),
            "errors": errs[:5],
        }
    return out