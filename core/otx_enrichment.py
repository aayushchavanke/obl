"""
AlienVault OTX threat intelligence enrichment helpers.

Adapter-style design keeps OTX as the first provider while allowing future
providers such as VirusTotal, AbuseIPDB, MISP, URLHaus, or HybridAnalysis
to implement the same interface.
"""

import ipaddress
import threading
import time
from collections import OrderedDict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import OTX_API_KEY, OTX_BASE_URL, OTX_TIMEOUT


DEFAULT_CACHE_TTL_SECONDS = 30 * 60
DEFAULT_CACHE_SIZE = 2048


class TTLRUCache:
    def __init__(self, maxsize=DEFAULT_CACHE_SIZE, ttl_seconds=DEFAULT_CACHE_TTL_SECONDS):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._store = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None

            expires_at, value = item
            if expires_at < time.time():
                self._store.pop(key, None)
                return None

            self._store.move_to_end(key)
            return value

    def set(self, key, value):
        with self._lock:
            self._store[key] = (time.time() + self.ttl_seconds, value)
            self._store.move_to_end(key)
            while len(self._store) > self.maxsize:
                self._store.popitem(last=False)


class ThreatIntelProvider:
    provider_name = "generic"

    def lookup_ip(self, indicator):
        raise NotImplementedError

    def lookup_domain(self, indicator):
        raise NotImplementedError

    def lookup_hash(self, indicator):
        raise NotImplementedError


class OTXAdapter(ThreatIntelProvider):
    provider_name = "AlienVault OTX"

    def __init__(self, api_key=None, base_url=None, timeout=None):
        self.api_key = api_key if api_key is not None else OTX_API_KEY
        self.base_url = (base_url or OTX_BASE_URL).rstrip("/")
        self.timeout = timeout or OTX_TIMEOUT
        self.session = requests.Session()

        retries = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def lookup_ip(self, indicator):
        return self._lookup_indicator("IPv4", indicator)

    def lookup_domain(self, indicator):
        return self._lookup_indicator("domain", indicator)

    def lookup_hash(self, indicator):
        return self._lookup_indicator("file", indicator)

    def _lookup_indicator(self, indicator_type, indicator):
        cache_key = f"{indicator_type}:{indicator}"
        cached = _OTX_CACHE.get(cache_key)
        if cached is not None:
            return cached

        if not self.api_key:
            result = _fallback_response(
                indicator=indicator,
                indicator_type=indicator_type,
                summary="OTX API key not configured.",
            )
            _OTX_CACHE.set(cache_key, result)
            return result

        url = f"{self.base_url}/api/v1/indicators/{indicator_type}/{indicator}/general"
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": "ObsidianLens/1.0",
        }

        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            if response.status_code != 200:
                result = _fallback_response(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    summary=f"OTX lookup returned HTTP {response.status_code}.",
                )
            else:
                payload = response.json()
                result = extract_otx_features(payload, indicator=indicator, indicator_type=indicator_type)
        except Exception as exc:
            result = _fallback_response(
                indicator=indicator,
                indicator_type=indicator_type,
                summary=f"OTX lookup failed: {exc}",
            )

        _OTX_CACHE.set(cache_key, result)
        return result


def _fallback_response(indicator, indicator_type, summary="OTX lookup unavailable."):
    return {
        "provider": "AlienVault OTX",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation_available": False,
        "malicious": False,
        "pulse_count": 0,
        "pulses": [],
        "pulse_names": [],
        "malware_tags": [],
        "malware_families": [],
        "country_name": "",
        "asn": "",
        "last_seen": "",
        "threat_reputation_summary": summary,
        "intel_severity": "none",
        "otx_score": 0.0,
    }


def _normalize_tags(items):
    normalized = []
    seen = set()
    for item in items:
        if not item:
            continue
        value = str(item).strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    return normalized


def _extract_last_seen(payload, pulses):
    candidate_fields = [
        payload.get("last_seen"),
        payload.get("latest"),
        payload.get("modified"),
        payload.get("last_updated"),
    ]

    for pulse in pulses:
        candidate_fields.extend([
            pulse.get("modified"),
            pulse.get("created"),
        ])

    for value in candidate_fields:
        if value:
            return str(value)
    return ""


def _extract_country(payload):
    geo = payload.get("geo", {}) if isinstance(payload.get("geo"), dict) else {}
    return (
        payload.get("country_name")
        or geo.get("country_name")
        or geo.get("country")
        or ""
    )


def _extract_asn(payload):
    return str(payload.get("asn") or payload.get("asn_name") or "")


def _severity_from_pulses(pulse_count):
    if pulse_count >= 10:
        return "critical"
    if pulse_count >= 4:
        return "high"
    if pulse_count >= 1:
        return "medium"
    return "none"


def extract_otx_features(otx_response, indicator="", indicator_type="IPv4"):
    pulse_info = otx_response.get("pulse_info", {}) if isinstance(otx_response, dict) else {}
    pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
    pulse_count = int(pulse_info.get("count") or len(pulses) or 0)

    pulse_names = []
    malware_tags = []
    malware_families = []
    pulse_summaries = []

    for pulse in pulses:
        pulse_name = pulse.get("name") or pulse.get("id") or "Unnamed Pulse"
        pulse_names.append(pulse_name)
        malware_tags.extend(pulse.get("tags", []) or [])

        families = pulse.get("malware_families") or pulse.get("adversary") or []
        if isinstance(families, str):
            families = [families]
        malware_families.extend(families)

        pulse_summaries.append({
            "name": pulse_name,
            "id": pulse.get("id", ""),
            "tags": _normalize_tags(pulse.get("tags", []) or []),
            "created": pulse.get("created", ""),
            "modified": pulse.get("modified", ""),
        })

    malware_tags = _normalize_tags(malware_tags)
    malware_families = _normalize_tags(malware_families)
    last_seen = _extract_last_seen(otx_response, pulses)
    country_name = _extract_country(otx_response)
    asn = _extract_asn(otx_response)
    malicious = pulse_count > 0
    severity = _severity_from_pulses(pulse_count)

    otx_score = min(1.0, pulse_count / 10.0)
    if malware_tags:
        otx_score = min(1.0, otx_score + min(0.2, len(malware_tags) * 0.03))
    if malware_families:
        otx_score = min(1.0, otx_score + min(0.15, len(malware_families) * 0.05))

    if malicious:
        summary = (
            f"OTX matched {pulse_count} threat pulse"
            f"{'s' if pulse_count != 1 else ''} for this {indicator_type.lower()}."
        )
    else:
        summary = f"No active OTX pulses were returned for this {indicator_type.lower()}."

    return {
        "provider": "AlienVault OTX",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation_available": True,
        "malicious": malicious,
        "pulse_count": pulse_count,
        "pulses": pulse_summaries,
        "pulse_names": _normalize_tags(pulse_names),
        "malware_tags": malware_tags,
        "malware_families": malware_families,
        "country_name": country_name,
        "asn": asn,
        "last_seen": last_seen,
        "threat_reputation_summary": summary,
        "intel_severity": severity,
        "otx_score": round(otx_score, 4),
    }


def check_ip_reputation(ip, api_key=None):
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return _fallback_response(ip, "IPv4", "Invalid IPv4 address.")

    provider = OTXAdapter(api_key=api_key)
    return provider.lookup_ip(ip)


def check_domain_reputation(domain, api_key=None):
    if not domain or "." not in str(domain):
        return _fallback_response(domain, "domain", "Invalid domain.")

    provider = OTXAdapter(api_key=api_key)
    return provider.lookup_domain(domain.strip().lower())


_OTX_CACHE = TTLRUCache()
