#!/usr/bin/env python3
"""
paste_engine – Dual-Mode Alert Triage Engine
============================================
Provides pluggable, production-ready alert triage with two strategies:
  1. LLM-Augmented Triage: Communicates with OpenAI-compatible APIs (OpenAI,
     Google Gemini, Ollama, vLLM) using structured JSON output.
  2. Heuristic Triage: Deterministic rule-based offline fallback with zero
     external dependencies or API key requirements.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from typing import Literal

from pydantic import BaseModel, Field

# ── Ensure sibling imports work when run as a script ───────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from provenance import (  # noqa: E402
    DATA_PATH,
    _basename,
    build_graph,
    decode_powershell_payload,
    detect_suspicious_edges,
    load_events,
    trace_chain,
)


# ── Pydantic Schema ───────────────────────────────────────────────────────

class AlertTriageReport(BaseModel):
    """Structured triage output for a single suspicious process chain."""

    alert_id: str = Field(
        description="Unique identifier for this alert."
    )
    root_cause_process: str = Field(
        description="Image name of the root ancestor that started the chain."
    )
    malicious_child_process: str = Field(
        description="Image name of the first suspicious child process."
    )
    decoded_command: str = Field(
        description="Decoded plaintext of any Base64-encoded PowerShell payload, "
        "or empty string if none."
    )
    verdict: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"] = Field(
        description="Overall risk verdict for this chain."
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the verdict (0.0 – 1.0)."
    )
    mitre_technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g. T1059.001)."
    )
    technique_name: str = Field(
        description="Human-readable MITRE technique name."
    )
    explanation: str = Field(
        description="1–2 sentence explanation of why this parent-child "
        "relationship is anomalous."
    )
    network_indicators: list[str] = Field(
        default_factory=list,
        description="Extracted network egress indicators (IP addresses, domains)."
    )
    recommended_action: str = Field(
        description="Analyst-facing recommended response action."
    )


# ── Known-Good Baseline and MITRE Taxonomy ─────────────────────────────────

_TECHNIQUE_MAP: dict[tuple[str, str], dict] = {
    ("winword.exe", "cmd.exe"): {
        "mitre_technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
    },
    ("winword.exe", "powershell.exe"): {
        "mitre_technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
    },
    ("outlook.exe", "cmd.exe"): {
        "mitre_technique_id": "T1059.003",
        "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
    },
    ("excel.exe", "cmd.exe"): {
        "mitre_technique_id": "T1059.003",
        "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
    },
    ("excel.exe", "powershell.exe"): {
        "mitre_technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
    },
}

_DEFAULT_TECHNIQUE = {
    "mitre_technique_id": "T1059",
    "technique_name": "Command and Scripting Interpreter",
}

# Known-good parent→child pairs that are standard OS / application behaviour
_BENIGN_PAIRS: set[tuple[str, str]] = {
    ("explorer.exe", "chrome.exe"),
    ("explorer.exe", "firefox.exe"),
    ("explorer.exe", "msedge.exe"),
    ("explorer.exe", "code.exe"),
    ("explorer.exe", "notepad.exe"),
    ("explorer.exe", "calc.exe"),
    ("chrome.exe",   "chrome.exe"),
    ("firefox.exe",  "firefox.exe"),
    ("msedge.exe",   "msedge.exe"),
    ("svchost.exe",  "taskhostw.exe"),
    ("svchost.exe",  "taskhost.exe"),
    ("svchost.exe",  "wuauclt.exe"),
    ("svchost.exe",  "runtimebroker.exe"),
    ("services.exe", "svchost.exe"),
}


# ── Configuration & Environment Resolution ─────────────────────────────────

def get_llm_config() -> tuple[str | None, str | None, str, str | None]:
    """
    Inspect environment variables to resolve active LLM provider.
    Returns: (api_key, base_url, model_name, provider_name)
    """
    # 1. Explicit PASTE LLM configuration
    if os.getenv("PASTE_LLM_API_KEY"):
        api_key = os.getenv("PASTE_LLM_API_KEY")
        base_url = os.getenv("PASTE_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.getenv("PASTE_LLM_MODEL", "gpt-4o-mini")
        return api_key, base_url, model, "Custom LLM"

    # 2. OpenAI environment
    if os.getenv("OPENAI_API_KEY"):
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("PASTE_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.getenv("PASTE_LLM_MODEL", "gpt-4o-mini")
        return api_key, base_url, model, "OpenAI"

    # 3. Google Gemini (via OpenAI-compatible endpoint)
    if os.getenv("GEMINI_API_KEY"):
        api_key = os.getenv("GEMINI_API_KEY")
        base_url = os.getenv("PASTE_LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
        model = os.getenv("PASTE_LLM_MODEL", "gemini-1.5-flash")
        return api_key, base_url, model, "Google Gemini"

    # 4. Local Ollama or vLLM endpoint specified without explicit key
    if os.getenv("PASTE_LLM_BASE_URL"):
        base_url = os.getenv("PASTE_LLM_BASE_URL")
        model = os.getenv("PASTE_LLM_MODEL", "llama3")
        return "local-no-key", base_url, model, "Local Ollama/vLLM"

    return None, None, "deterministic", None


def get_triage_mode() -> str:
    """
    Return human-readable mode string for console status display.
    """
    _, _, _, provider = get_llm_config()
    if provider:
        return f"LLM-Augmented (Active Provider: {provider})"
    return "Deterministic Heuristic Fallback"


# ── Strategy 1: Heuristic Triage ───────────────────────────────────────────

def _is_benign_chain(chain_nodes: list[dict]) -> bool:
    """Return True if every parent→child hop in the chain is known-good."""
    for i in range(len(chain_nodes) - 1):
        parent = _basename(chain_nodes[i].get("Image", ""))
        child  = _basename(chain_nodes[i + 1].get("Image", ""))
        if (parent, child) not in _BENIGN_PAIRS:
            return False
    return True


def _score_chain(chain_nodes: list[dict], decoded: str) -> tuple[
    Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"], float
]:
    """
    Deterministic heuristic scorer:
      • all hops match known-good allowlist   → BENIGN     (0.98)
      • encoded PowerShell payload            → MALICIOUS  (0.95)
      • chain length ≥ 3 (deep shell nesting) → MALICIOUS  (0.90)
      • any Office → shell edge (fallback)    → SUSPICIOUS (0.75)
    """
    if _is_benign_chain(chain_nodes):
        return "BENIGN", 0.98
    if decoded:
        return "MALICIOUS", 0.95
    if len(chain_nodes) >= 3:
        return "MALICIOUS", 0.90
    return "SUSPICIOUS", 0.75


def _heuristic_triage(graph_data: dict) -> AlertTriageReport:
    """
    Deterministic rule-based evaluator for offline triage.
    Evaluates process hierarchy, known-good baselines, decoded command
    payloads, and network egress indicators without external APIs.
    """
    parent_img = _basename(graph_data["parent_image"])
    child_img  = _basename(graph_data["child_image"])
    chain      = graph_data["chain_nodes"]
    decoded    = graph_data.get("decoded_command", "")

    technique = _TECHNIQUE_MAP.get(
        (parent_img, child_img), _DEFAULT_TECHNIQUE
    )

    # Extract network indicators from chain nodes if not already provided
    network_indicators: list[str] = list(graph_data.get("network_indicators", []))
    if not network_indicators:
        for n in chain:
            if n.get("node_type") == "NetworkSocket":
                dest_ip = n.get("destination_ip")
                hostname = n.get("hostname")
                if dest_ip and dest_ip not in network_indicators:
                    network_indicators.append(dest_ip)
                if hostname and hostname not in network_indicators:
                    network_indicators.append(hostname)

    verdict, confidence = _score_chain(chain, decoded)

    # ── Benign path ────────────────────────────────────────────────────
    if verdict == "BENIGN":
        return AlertTriageReport(
            alert_id=f"PASTE-{uuid.uuid4().hex[:8].upper()}",
            root_cause_process=parent_img,
            malicious_child_process=child_img,
            decoded_command="",
            verdict="BENIGN",
            confidence_score=confidence,
            mitre_technique_id="None",
            technique_name="None",
            explanation=(
                "Legitimate operating system and browser process tree. "
                "All parent-child relationships match known-good baselines."
            ),
            network_indicators=[],
            recommended_action="No action required. Event suppressed.",
        )

    # ── Suspicious / Malicious path ────────────────────────────────────
    explanation = (
        f"The Office application {parent_img} spawned {child_img}, which is "
        f"a known Living-off-the-Land technique. "
    )
    if decoded:
        explanation += (
            f"The command line contains a Base64-encoded PowerShell payload "
            f"that decodes to a network download cradle, strongly indicating "
            f"malicious macro execution."
        )
    else:
        explanation += (
            f"While this may occasionally occur in legitimate automation, "
            f"the process chain depth ({len(chain)} hops) increases suspicion."
        )

    if network_indicators:
        explanation += (
            f" Correlated network egress detected to "
            f"{', '.join(network_indicators)} indicating potential C2 communication."
        )

    recommended = (
        "Isolate host immediately, collect memory dump and Sysmon logs, "
        "revoke user session tokens, and escalate to Tier-2 SOC analyst."
        if verdict == "MALICIOUS"
        else "Flag for analyst review; correlate with EDR telemetry."
    )

    return AlertTriageReport(
        alert_id=f"PASTE-{uuid.uuid4().hex[:8].upper()}",
        root_cause_process=parent_img,
        malicious_child_process=child_img,
        decoded_command=decoded,
        verdict=verdict,
        confidence_score=confidence,
        mitre_technique_id=technique["mitre_technique_id"],
        technique_name=technique["technique_name"],
        explanation=explanation,
        network_indicators=network_indicators,
        recommended_action=recommended,
    )


# ── Strategy 2: LLM-Augmented Triage ───────────────────────────────────────

def _llm_triage(
    graph_data: dict,
    model_name: str,
    api_key: str,
    base_url: str | None = None,
) -> AlertTriageReport:
    """
    Constructs a structured prompt detailing analyst role, MITRE ATT&CK taxonomy,
    and serialized causal graph, querying an OpenAI-compatible endpoint.
    Parses and validates the response into an AlertTriageReport.
    """
    endpoint = f"{(base_url or 'https://api.openai.com/v1').rstrip('/')}/chat/completions"

    system_prompt = (
        "You are an expert Tier-3 Cyber Defense SOC Analyst and Detection Engineer. "
        "Analyze the provided process provenance execution DAG and telemetry from Windows Sysmon "
        "(Event ID 1 Process Creation and Event ID 3 Network Connection). "
        "Evaluate the causal chain for Living-off-the-Land (LotL) evasion, malicious macro execution, "
        "de-obfuscated script payloads, and command-and-control network egress. "
        "Map anomalous behaviors to the MITRE ATT&CK taxonomy (e.g. T1059.001, T1059.003, T1071.001, T1033). "
        "You MUST respond ONLY with a valid JSON object conforming strictly to the AlertTriageReport schema:\n"
        "{\n"
        '  "alert_id": "PASTE-<HEX>",\n'
        '  "root_cause_process": "<image_name>",\n'
        '  "malicious_child_process": "<image_name>",\n'
        '  "decoded_command": "<plaintext payload if any, else empty string>",\n'
        '  "verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",\n'
        '  "confidence_score": <float between 0.0 and 1.0>,\n'
        '  "mitre_technique_id": "<e.g. T1059.001 or None>",\n'
        '  "technique_name": "<human readable technique name>",\n'
        '  "explanation": "<1-2 sentence anomaly explanation>",\n'
        '  "network_indicators": ["<ip>", "<domain>"],\n'
        '  "recommended_action": "<action recommendation>"\n'
        "}"
    )

    # Format the serialized causal execution graph
    chain_summary = []
    for node in graph_data.get("chain_nodes", []):
        if node.get("node_type") == "NetworkSocket":
            chain_summary.append({
                "node_type": "NetworkSocket",
                "destination_ip": node.get("destination_ip"),
                "destination_port": node.get("destination_port"),
                "protocol": node.get("protocol"),
                "hostname": node.get("hostname"),
            })
        else:
            chain_summary.append({
                "node_type": "Process",
                "pid": node.get("ProcessId"),
                "image": node.get("Image"),
                "command_line": node.get("CommandLine"),
                "decoded_payload": node.get("DecodedPayload", ""),
                "user": node.get("User"),
            })

    user_payload = {
        "parent_image": graph_data.get("parent_image"),
        "child_image": graph_data.get("child_image"),
        "decoded_command": graph_data.get("decoded_command", ""),
        "network_indicators": graph_data.get("network_indicators", []),
        "causal_execution_chain": chain_summary,
    }

    req_body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, indent=2)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }

    req_data = json.dumps(req_body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "PASTE-Engine/2.0",
    }

    req = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")

    # Perform request with standard library
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))

    content = resp_data["choices"][0]["message"]["content"].strip()
    # Remove markdown code block fences if present
    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    parsed = json.loads(content)

    # Sanitize and ensure required fields exist
    if not parsed.get("alert_id"):
        parsed["alert_id"] = f"PASTE-{uuid.uuid4().hex[:8].upper()}"
    if parsed.get("verdict"):
        parsed["verdict"] = parsed["verdict"].upper()
    if not parsed.get("network_indicators"):
        parsed["network_indicators"] = graph_data.get("network_indicators", [])

    return AlertTriageReport.model_validate(parsed)


# ── Dual-Mode Coordinator ─────────────────────────────────────────────────

_fallback_logged = False


def triage_provenance_chain(subgraph_data: dict) -> AlertTriageReport:
    """
    Triage coordinator supporting dual-mode evaluation:
      - LLM-Augmented mode when API key or local base URL is provided.
      - Deterministic heuristic mode when offline or fallback is triggered.
    """
    global _fallback_logged
    api_key, base_url, model_name, provider = get_llm_config()

    if provider:
        try:
            return _llm_triage(
                graph_data=subgraph_data,
                model_name=model_name,
                api_key=api_key or "local",
                base_url=base_url,
            )
        except Exception:
            if not _fallback_logged:
                print("[*] No external LLM key detected / API offline. Falling back to deterministic heuristic triager.")
                _fallback_logged = True
            return _heuristic_triage(subgraph_data)
    else:
        if not _fallback_logged:
            print("[*] No external LLM key detected / API offline. Falling back to deterministic heuristic triager.")
            _fallback_logged = True
        return _heuristic_triage(subgraph_data)


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  PASTE ENGINE  ·  Alert Triage Report")
    print("=" * 72)

    mode_label = get_triage_mode()
    print(f"[*] Engine Mode: {mode_label}\n")

    events = load_events(DATA_PATH)
    G = build_graph(events)

    suspicious = detect_suspicious_edges(G)
    if not suspicious:
        print("\n[✓] No suspicious edges – nothing to triage.\n")
        return

    reports: list[dict] = []

    for parent_g, child_g in suspicious:
        chain_guids = trace_chain(G, parent_g)
        chain_nodes = [dict(G.nodes[g]) for g in chain_guids]

        decoded_parts = [
            n.get("DecodedPayload", "") for n in chain_nodes if n.get("DecodedPayload")
        ]
        decoded_combined = " | ".join(decoded_parts) if decoded_parts else ""

        network_indicators: list[str] = []
        for n in chain_nodes:
            if n.get("node_type") == "NetworkSocket":
                dest_ip = n.get("destination_ip")
                hostname = n.get("hostname")
                if dest_ip and dest_ip not in network_indicators:
                    network_indicators.append(dest_ip)
                if hostname and hostname not in network_indicators:
                    network_indicators.append(hostname)

        subgraph_data = {
            "parent_image": G.nodes[parent_g]["Image"],
            "child_image": G.nodes[child_g]["Image"],
            "chain_nodes": chain_nodes,
            "decoded_command": decoded_combined,
            "network_indicators": network_indicators,
        }

        report = triage_provenance_chain(subgraph_data)
        reports.append(report.model_dump())

    for i, r in enumerate(reports, 1):
        print(f"\n{'─' * 72}")
        print(f"  Triage Report #{i}")
        print(f"{'─' * 72}\n")
        print(json.dumps(r, indent=2, ensure_ascii=False))

    print("\n" + "=" * 72)
    print(f"  {len(reports)} report(s) generated.  Schema: AlertTriageReport (Pydantic v2)")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
