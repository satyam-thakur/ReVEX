import json
import os
import time
import hashlib
import logging
from pathlib import Path
from dataclasses import asdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

import requests


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cache directory configuration
CACHE_DIR = Path("vul_analysis") / ".cache" / "nvd"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True, slots=True)
class NvdCveSummary:
    """Small, stable subset of NVD CVE payload used for downstream LLM decisioning."""

    cve_id: str
    source_identifier: Optional[str]
    published: Optional[str]
    last_modified: Optional[str]

    description: Optional[str]

    cvss_v31_vector: Optional[str]
    cvss_v31_base_score: Optional[float]
    cvss_v31_severity: Optional[str]

    weaknesses: List[str]
    references: List[str]


class NvdApiError(RuntimeError):
    pass


class NVDIntelTool:
    """Fetch CVE intel from NVD and return a compact evidence blob.

    Designed to be used as a DSPy ReAct tool (callable object).

    Notes:
        - Uses env var NVD_API_KEY by default.
        - Returns a string so the LLM can cite it in `tool_evidence`.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.environ.get("NVD_API_KEY")

    def __call__(self, cve_id: str) -> str:
        cve: NvdCveSummary = fetch_cve_from_nvd(cve_id, api_key=self._api_key)
        payload = asdict(cve)
        return "=== NVD Intel (CVE API 2.0) ===\n" + json.dumps(payload, indent=2, sort_keys=True)


def _pick_english_description(descriptions: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    if not descriptions:
        return None
    for d in descriptions:
        if d.get("lang") == "en" and d.get("value"):
            return str(d.get("value"))
    # fallback to first non-empty
    for d in descriptions:
        if d.get("value"):
            return str(d.get("value"))
    return None


def _extract_cvss(metrics: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """Extract CVSS data with V3.1 > V3.0 > V2 fallback for older CVEs."""
    if not metrics:
        return (None, None, None)

    # Try CVSS V3.1, V3.0, then fallback to V2 for older CVEs
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            metric = entries[0] or {}
            cvss = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
            vector = cvss.get("vectorString")
            score = cvss.get("baseScore")
            # V2 uses different severity field names
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
            try:
                score_f = float(score) if score is not None else None
            except (TypeError, ValueError):
                score_f = None
            return (
                str(vector) if vector else None,
                score_f,
                str(severity) if severity else None,
            )

    return (None, None, None)


def _get_cache_path(cve_id: str) -> Path:
    """Generate a cache path for the CVE ID."""
    safe_id = cve_id.replace(":", "_").replace("/", "_")  # Just in case
    return CACHE_DIR / f"{safe_id}.json"


def fetch_cve_from_nvd(
    cve_id: str,
    *,
    api_key: Optional[str] = None,
    timeout_s: float = 20.0,
    max_retries: int = 3,
    backoff_s: float = 1.5,
) -> NvdCveSummary:
    """Fetch CVE details from NVD (CVE API 2.0).

    Args:
        cve_id: CVE identifier like "CVE-2024-21762".
        api_key: Optional NVD key; defaults to env NVD_API_KEY.
        timeout_s: HTTP timeout.
        max_retries: Retries on transient errors / rate limits.
        backoff_s: Exponential backoff base.

    Returns:
        Parsed NvdCveSummary.

    Raises:
        NvdApiError: if request fails or the CVE is not found.
    """

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise NvdApiError(f"Invalid CVE ID: {cve_id!r}")

    # Check cache first
    cache_path = _get_cache_path(cve_id)
    logger = logging.getLogger(__name__)
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
            
            # Validate cache has content - if empty/invalid, delete and re-fetch
            if not cached_data.get("description") and not cached_data.get("cve_id"):
                logger.info(f"NVD cache empty for {cve_id}, re-fetching...")
                cache_path.unlink()  # Delete invalid cache
            else:
                logger.info(f"NVD cache hit for {cve_id}:\n{cached_data}")
                return NvdCveSummary(**cached_data)
        except Exception:
            pass  # Fallback to fetch on cache error

    key = api_key or os.environ.get("NVD_API_KEY")
    if not key:
        raise NvdApiError("Missing NVD_API_KEY environment variable")
    
    # Proactive rate limiting sleep 
    # With Key: ~0.6s recommended (50 req / 30s)
    # Without Key: ~6.0s recommended (5 req / 30s)
    sleep_time = 0.6 if key else 6.0
    time.sleep(sleep_time)

    headers = {
        "Accept": "application/json",
        # NVD requires apiKey header (case-insensitive). Using standard capitalization.
        "apiKey": key,
        "User-Agent": "LLM-Assisted-Container-Security-Analysis/1.0",
    }
    params = {"cveId": cve_id}

    last_err: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(NVD_CVE_API_URL, headers=headers, params=params, timeout=timeout_s)

            # Basic handling for NVD rate limiting
            if resp.status_code in (429, 503):
                raise NvdApiError(f"NVD rate-limited/unavailable (HTTP {resp.status_code})")

            if resp.status_code != 200:
                raise NvdApiError(f"NVD request failed (HTTP {resp.status_code}): {resp.text[:500]}")

            payload = resp.json()
            vulns = payload.get("vulnerabilities")
            if not isinstance(vulns, list) or not vulns:
                raise NvdApiError(f"CVE not found in NVD response: {cve_id}")

            cve = (vulns[0] or {}).get("cve", {})
            if not isinstance(cve, dict):
                raise NvdApiError(f"Malformed NVD payload for {cve_id}")

            descriptions = cve.get("descriptions")
            description = _pick_english_description(descriptions)

            metrics = cve.get("metrics")
            vector, score, severity = _extract_cvss(metrics)

            # CWE IDs/names can appear in weaknesses[].description[].value
            weaknesses: List[str] = []
            for w in cve.get("weaknesses", []) or []:
                for d in (w or {}).get("description", []) or []:
                    v = d.get("value")
                    if v:
                        weaknesses.append(str(v))

            # NOTE: References muted to reduce log verbosity and LLM token usage
            references: List[str] = []
            for r in cve.get("references", []) or []:
                url = (r or {}).get("url")
                if url:
                    references.append(str(url))
            # references: List[str] = []  # Empty list - references extraction disabled

            summary = NvdCveSummary(
                cve_id=str(cve.get("id") or cve_id),
                source_identifier=str(cve.get("sourceIdentifier")) if cve.get("sourceIdentifier") else None,
                published=str(cve.get("published")) if cve.get("published") else None,
                last_modified=str(cve.get("lastModified")) if cve.get("lastModified") else None,
                description=description,
                cvss_v31_vector=vector,
                cvss_v31_base_score=score,
                cvss_v31_severity=severity,
                weaknesses=weaknesses,
                references=references[:3],
            )

            # Save to cache
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(asdict(summary), f, indent=2)
            except Exception:
                pass  # Ignore cache write errors

            return summary

        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt >= max_retries:
                break
            sleep_s = backoff_s * (2**attempt)
            time.sleep(sleep_s)

    raise NvdApiError(f"Failed to fetch {cve_id}: {last_err}")
