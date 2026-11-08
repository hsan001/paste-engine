#!/usr/bin/env python3
"""
paste_engine – Detection-as-Code Synthesizer (Phase 3)
======================================================
Consumes an ``AlertTriageReport`` from the triage module and generates a
production-grade Sigma v2 YAML rule, then writes it to disk.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import date, timezone

import yaml

# ── Sibling imports ────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from triage import (  # noqa: E402
    AlertTriageReport,
    DATA_PATH,
    build_graph,
    detect_suspicious_edges,
    load_events,
    triage_provenance_chain,
    trace_chain,
)
from provenance import _basename  # noqa: E402

# ── Output path ───────────────────────────────────────────────────────────
RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
RULE_PATH = os.path.join(RULES_DIR, "sigma_auto_rule.yml")


# ── Sigma Rule Generator ─────────────────────────────────────────────────

def generate_sigma_rule(triage_report: AlertTriageReport) -> str:
    """
    Build a valid Sigma v2 YAML document from a triage report.

    Returns the rendered YAML string.
    """
    technique_id = triage_report.mitre_technique_id
    mitre_url = (
        "https://attack.mitre.org/techniques/"
        + technique_id.replace(".", "/")
    )

    # Deterministic UUID seeded from the technique + root process
    rule_uuid = str(uuid.uuid5(
        uuid.NAMESPACE_DNS,
        f"paste_engine.{technique_id}.{triage_report.root_cause_process}",
    ))

    rule = {
        "title": (
            "Suspicious Living-off-the-Land Process Spawned by "
            "Office Application"
        ),
        "id": rule_uuid,
        "status": "experimental",
        "description": triage_report.explanation,
        "references": [mitre_url],
        "author": "Mohammad Hassan Jalal (PASTE Autonomous Engine)",
        "date": date.today().strftime("%Y-%m-%d"),
        "tags": [
            "attack.execution",
            f"attack.{technique_id.lower()}",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_parent": {
                "ParentImage|endswith": [
                    "\\WINWORD.EXE",
                    "\\EXCEL.EXE",
                    "\\OUTLOOK.EXE",
                ],
            },
            "selection_child": {
                "Image|endswith": [
                    "\\cmd.exe",
                    "\\powershell.exe",
                    "\\pwsh.exe",
                ],
            },
            "selection_flags": {
                "CommandLine|contains": [
                    "-enc",
                    "-encodedcommand",
                    "whoami",
                ],
            },
            "condition": (
                "selection_parent and selection_child and selection_flags"
            ),
        },
        "falsepositives": [
            "Administrative macros or third-party add-ins (rare)",
        ],
        "level": "high",
    }

    # PyYAML: default_flow_style=False gives block style;
    # sort_keys=False preserves insertion order.
    return yaml.dump(
        rule,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  PASTE ENGINE  ·  Detection-as-Code Synthesizer")
    print("=" * 72)

    # ── Replay the triage pipeline to get a report ─────────────────────
    events = load_events(DATA_PATH)
    G = build_graph(events)
    suspicious = detect_suspicious_edges(G)

    if not suspicious:
        print("\n[✓] Nothing to synthesize – no suspicious edges.\n")
        return

    parent_g, child_g = suspicious[0]
    chain_guids = trace_chain(G, parent_g)
    chain_nodes = [dict(G.nodes[g]) for g in chain_guids]
    decoded_parts = [
        n.get("DecodedPayload", "")
        for n in chain_nodes if n.get("DecodedPayload")
    ]

    subgraph_data = {
        "parent_image": G.nodes[parent_g]["Image"],
        "child_image": G.nodes[child_g]["Image"],
        "chain_nodes": chain_nodes,
        "decoded_command": " | ".join(decoded_parts) if decoded_parts else "",
    }

    report = triage_provenance_chain(subgraph_data)

    # ── Generate the Sigma rule ────────────────────────────────────────
    sigma_yaml = generate_sigma_rule(report)

    os.makedirs(RULES_DIR, exist_ok=True)
    with open(RULE_PATH, "w", encoding="utf-8") as fh:
        fh.write(sigma_yaml)

    print(f"\n[*] Triage verdict : {report.verdict}  "
          f"(confidence {report.confidence_score:.0%})")
    print(f"[*] MITRE technique: {report.mitre_technique_id} – "
          f"{report.technique_name}")
    print(f"\n[+] Sigma rule written → {RULE_PATH}\n")
    print("─" * 72)
    print("  Generated Sigma YAML")
    print("─" * 72 + "\n")
    print(sigma_yaml)
    print("=" * 72)
    print("  Synthesis complete.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
