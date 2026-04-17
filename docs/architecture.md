# Architecture

- threat_api: ingest -> normalize -> trust score -> correlate -> enrich -> STIX
- log_api: parse -> detect (4 engines) -> aggregate -> report -> STIX
- both are independently deployable services
- OpenCTI receives STIX bundles from each service