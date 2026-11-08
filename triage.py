#!/usr/bin/env python3
"""
paste_engine – Alert Triage Report Generator
=============================================
Uses the provenance graph from provenance.py to generate a structured
Pydantic-validated triage report for each detected malicious lineage.
Runs fully offline with a deterministic local evaluator (no API key needed).
"""

from __future__ import annotations

import json
import os
import sys
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
    recommended_action: str = Field(
        description="Analyst-facing recommended response action."
    )


# ── Local / Mock Evaluator ─────────────────────────────────────────────────
# Maps (parent_basename, child_basename) → partial triage fields.
# This deterministic rule engine runs entirely offline.

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
    ("svchost.exe",  "RuntimeBroker.exe".lower()),
    ("services.exe", "svchost.exe"),
}


def _is_benign_chain(chain_nodes: list[dict]) -> bool:
    """Return True if every parent→child hop in the chain is known-good."""
    from provenance import _basename  # already imported at module level
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
    Heuristic scorer:
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


def triage_provenance_chain(subgraph_data: dict) -> AlertTriageReport:
    """
    Accept a dict describing a suspicious provenance chain and return a
    validated ``AlertTriageReport``.

    Expected keys in *subgraph_data*:
        parent_image, child_image, chain_nodes (list[dict]),
        decoded_command (str)
    """
    parent_img = _basename(subgraph_data["parent_image"])
    child_img  = _basename(subgraph_data["child_image"])
    chain      = subgraph_data["chain_nodes"]
    decoded    = subgraph_data.get("decoded_command", "")

    technique = _TECHNIQUE_MAP.get(
        (parent_img, child_img), _DEFAULT_TECHNIQUE
    )

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
        recommended_action=recommended,
    )


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  PASTE ENGINE  ·  Alert Triage Report")
    print("=" * 72)

    events = load_events(DATA_PATH)
    G = build_graph(events)

    suspicious = detect_suspicious_edges(G)
    if not suspicious:
        print("\n[✓] No suspicious edges – nothing to triage.\n")
        return

    reports: list[dict] = []

    for parent_g, child_g in suspicious:
        # Reconstruct the full chain from root → leaf
        chain_guids = trace_chain(G, parent_g)
        chain_nodes = [dict(G.nodes[g]) for g in chain_guids]

        # Collect any decoded payloads from nodes in the chain
        decoded_parts = [
            n.get("DecodedPayload", "") for n in chain_nodes if n.get("DecodedPayload")
        ]
        decoded_combined = " | ".join(decoded_parts) if decoded_parts else ""

        subgraph_data = {
            "parent_image": G.nodes[parent_g]["Image"],
            "child_image": G.nodes[child_g]["Image"],
            "chain_nodes": chain_nodes,
            "decoded_command": decoded_combined,
        }

        report = triage_provenance_chain(subgraph_data)
        reports.append(report.model_dump())

    # Pretty-print
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
