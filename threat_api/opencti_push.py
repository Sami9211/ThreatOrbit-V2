def push_stix_to_opencti(opencti_url: str, api_key: str, bundle: dict) -> dict:
    """
    Safe placeholder connector response.
    Keeps API stable while avoiding broken assumptions about OpenCTI upload flow.
    """
    if not opencti_url or not api_key:
        return {"ok": False, "error": "OPENCTI_URL or OPENCTI_API_KEY not configured"}

    return {
        "ok": False,
        "error": "Direct OpenCTI push requires connector-specific upload flow. Use /stix/export and import in OpenCTI UI."
    }
