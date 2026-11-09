#!/usr/bin/env python3
"""
paste_engine – OSINT Threat Intelligence Enricher (Phase 5)
===========================================================
Enriches extracted indicators of compromise (IP addresses, domain names)
with threat intelligence: ISP/Organization, Country, Threat Classification,
and Abuse Confidence Score. Includes a local offline database mock.
"""

from __future__ import annotations

import os
import re
from typing import Any

# ── Local Curated Threat Intelligence Mock Database ───────────────────────
_LOCAL_INTEL_DB: dict[str, dict[str, Any]] = {
    "198.51.100.42": {
        "ip": "198.51.100.42",
        "isp": "FlyServers S.A. / Bulletproof VPS Hosting",
        "country": "Netherlands (NL)",
        "threat_classification": "Known Cobalt Strike C2 / Bulletproof Hosting",
        "abuse_confidence_score": 100,
        "is_malicious": True,
        "threat_actor": "UNC2452 / APT29 Associated",
        "last_reported": "2026-11-09T06:00:00Z",
    },
    "192.168.1.50": {
        "ip": "192.168.1.50",
        "isp": "RFC1918 Private Subnet (Staging)",
        "country": "Internal LAN",
        "threat_classification": "Internal Download Staging Server",
        "abuse_confidence_score": 75,
        "is_malicious": True,
        "threat_actor": "Lateral Movement / Internal Cradle",
        "last_reported": "2026-11-09T08:00:00Z",
    },
    "142.250.190.46": {
        "ip": "142.250.190.46",
        "isp": "Google LLC",
        "country": "United States (US)",
        "threat_classification": "Legitimate CDN / Search Service",
        "abuse_confidence_score": 0,
        "is_malicious": False,
        "threat_actor": "None",
        "last_reported": "2026-11-09T00:00:00Z",
    },
}


def _is_private_ip(ip: str) -> bool:
    """Check if IP belongs to private/loopback RFC1918 space."""
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)", ip))


def enrich_iocs(ip_list: list[str]) -> dict[str, dict[str, Any]]:
    """
    Enrich a list of IP addresses with structured OSINT threat intelligence.

    Args:
        ip_list: List of IPv4 address strings.

    Returns:
        Dictionary mapping each IP to its threat intelligence attributes:
        - isp: Organization / Network Provider
        - country: Geolocation country code & name
        - threat_classification: Categorization (e.g. Cobalt Strike C2)
        - abuse_confidence_score: Integer (0-100%)
    """
    results: dict[str, dict[str, Any]] = {}

    for ip in ip_list:
        clean_ip = ip.split(":")[0].strip()
        if not clean_ip:
            continue

        # 1. Check curated offline database first
        if clean_ip in _LOCAL_INTEL_DB:
            results[clean_ip] = dict(_LOCAL_INTEL_DB[clean_ip])
            continue

        # 2. Check if private / internal IP
        if _is_private_ip(clean_ip):
            results[clean_ip] = {
                "ip": clean_ip,
                "isp": "RFC1918 Private Network",
                "country": "Internal / Local LAN",
                "threat_classification": "Internal Host / Gateway",
                "abuse_confidence_score": 0,
                "is_malicious": False,
                "threat_actor": "None",
                "last_reported": "N/A",
            }
            continue

        # 3. Dynamic generic OSINT assessment for other external IPs
        results[clean_ip] = {
            "ip": clean_ip,
            "isp": "Unknown External Hosting Provider",
            "country": "External Autonomous System",
            "threat_classification": "Uncategorized External IP",
            "abuse_confidence_score": 40,
            "is_malicious": False,
            "threat_actor": "Unattributed",
            "last_reported": "N/A",
        }

    return results


def format_threat_intel_summary(intel_results: dict[str, dict[str, Any]]) -> str:
    """Format threat intelligence results into a human-readable one-line summary."""
    summaries = []
    for ip, data in intel_results.items():
        classification = data.get("threat_classification", "Unknown")
        abuse = data.get("abuse_confidence_score", 0)
        country = data.get("country", "Unknown")
        summaries.append(f"{ip} -> {classification} (Abuse: {abuse}%, {country})")
    return " | ".join(summaries)


if __name__ == "__main__":
    test_ips = ["198.51.100.42", "192.168.1.105", "142.250.190.46"]
    enriched = enrich_iocs(test_ips)
    print("Enrichment Results:")
    for ip, record in enriched.items():
        print(f"  {ip}: {record['threat_classification']} ({record['isp']}, {record['country']}) - Abuse: {record['abuse_confidence_score']}%")
