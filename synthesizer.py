#!/usr/bin/env python3
"""
paste_engine – Detection-as-Code Synthesizer (Phase 3)
======================================================
Consumes an ``AlertTriageReport`` from the triage module and dynamically
generates a production-grade Sigma v2 YAML rule based on the triage output,
then writes it to disk.
"""

from __future__ import annotations

import os
import re
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


# ── Token & Flag Extraction ───────────────────────────────────────────────

def extract_command_tokens(decoded_command: str) -> list[str]:
    """
    Dynamically extract non-empty tokens, flags, and suspicious keywords
    from a decoded command string for use in CommandLine|contains.
    """
    tokens: list[str] = []

    # Check for presence of common suspicious keywords / LOLBIN flags
    known_suspicious = [
        "-enc", "-encodedcommand", "whoami", "powershell", "pwsh",
        "bypass", "hidden", "invoke-webrequest", "downloadstring", "downloadfile"
    ]
    lower_cmd = decoded_command.lower() if decoded_command else ""
    for kw in known_suspicious:
        if kw in lower_cmd and kw not in tokens:
            tokens.append(kw)

    # Extract flags and command/cmdlet tokens directly from the payload
    if decoded_command:
        # Split on whitespace, quotes, and pipes
        raw_words = re.split(r'[\s"\'|]+', decoded_command)
        for word in raw_words:
            w = word.strip()
            if not w or len(w) < 2:
                continue
            # Pick up flags (-Uri, -ep), cmdlets with hyphens, or target binaries (.exe)
            if w.startswith("-") or w.lower().endswith(".exe") or "-" in w:
                if w not in tokens:
                    tokens.append(w)

    # Fallback to general suspicious command indicators if none extracted
    if not tokens:
        tokens = ["-enc", "-encodedcommand", "whoami"]

    return tokens


# ── Sigma Rule Generator ─────────────────────────────────────────────────

def generate_sigma_rule(triage_report: AlertTriageReport) -> str:
    """
    Build a valid Sigma v2 YAML document dynamically synthesized from a triage report.

    Extracts parent, child, and command line tokens directly from the alert triage
    report rather than relying on hardcoded process templates.
    """
    technique_id = triage_report.mitre_technique_id
    mitre_url = (
        "https://attack.mitre.org/techniques/"
        + technique_id.replace(".", "/")
    )

    parent_filename = os.path.basename(triage_report.root_cause_process)
    child_filename = os.path.basename(triage_report.malicious_child_process)

    # Extract non-empty tokens and flags from decoded_command
    tokens = extract_command_tokens(triage_report.decoded_command)

    # Deterministic UUID seeded from technique + root process + child process
    rule_uuid = str(uuid.uuid5(
        uuid.NAMESPACE_DNS,
        f"paste_engine.{technique_id}.{parent_filename}.{child_filename}",
    ))

    technique_label = triage_report.technique_name or "Living-off-the-Land Execution"
    title = f"Suspicious {child_filename} Spawned by {parent_filename} ({technique_label})"

    tags = [
        "attack.execution",
        f"attack.{technique_id.lower()}",
    ]
    if triage_report.network_indicators:
        tags.extend([
            "attack.command_and_control",
            "attack.t1071.001",
        ])

    description = triage_report.explanation
    if triage_report.network_indicators and "network egress" not in description.lower():
        description += (
            f" Correlated network egress detected to "
            f"{', '.join(triage_report.network_indicators)}."
        )

    rule = {
        "title": title,
        "id": rule_uuid,
        "status": "experimental",
        "description": description,
        "references": [mitre_url],
        "author": "Mohammad Hassan Jalal (PASTE Autonomous Engine)",
        "date": date.today().strftime("%Y-%m-%d"),
        "tags": tags,
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_parent": {
                "ParentImage|endswith": [f"\\{parent_filename}"],
            },
            "selection_child": {
                "Image|endswith": [f"\\{child_filename}"],
            },
            "selection_flags": {
                "CommandLine|contains": tokens,
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
