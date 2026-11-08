#!/usr/bin/env python3
"""
paste_engine – Automated End-to-End Detection Pipeline Driver
=============================================================
Ties together every PASTE phase in a single CLI entrypoint:

  Phase 1 – Provenance graph reconstruction + PowerShell de-obfuscation
  Phase 2 – Structured Pydantic triage (AlertTriageReport)
  Phase 3 – Sigma rule synthesis + SIEM query compilation (if MALICIOUS)

Usage:
    python paste_engine/main.py [--input <path/to/sysmon.json>]
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone

# ── Sibling import path setup ──────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

# ── PyYAML C-extension shim (required before any pySigma import) ──────────
import yaml
if not hasattr(yaml, "CSafeLoader"):
    yaml.CSafeLoader = yaml.SafeLoader          # type: ignore[attr-defined]
if not hasattr(yaml, "CDumper"):
    yaml.CDumper = yaml.Dumper                  # type: ignore[attr-defined]

# ── PASTE module imports ──────────────────────────────────────────────────
from provenance import (
    build_graph,
    detect_suspicious_edges,
    load_events,
    print_ascii_tree,
    trace_chain,
    _basename,
)
from triage import (
    AlertTriageReport,
    triage_provenance_chain,
)
from synthesizer import (
    RULE_PATH,
    RULES_DIR,
    generate_sigma_rule,
)
from validator import (
    validate_and_compile,
    _header,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _banner(text: str, width: int = 72, char: str = "═") -> None:
    print(char * width)
    print(f"  {text}")
    print(char * width)


def _phase(label: str, width: int = 72) -> None:
    print(f"\n{'─' * width}")
    print(f"  {label}")
    print(f"{'─' * width}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline Phases
# ─────────────────────────────────────────────────────────────────────────────

def phase1_provenance(input_path: str):
    """Load events, build graph, detect suspicious edges, print ASCII tree."""
    _phase("PHASE 1 — Provenance Graph Reconstruction & De-obfuscation")

    events = load_events(input_path)
    print(f"[*] Source      : {input_path}")
    print(f"[*] Events loaded : {len(events)} Sysmon Event-ID-1 record(s)\n")

    G = build_graph(events)
    print(f"[*] Graph       : {G.number_of_nodes()} nodes, "
          f"{G.number_of_edges()} edges\n")

    suspicious = detect_suspicious_edges(G)
    if not suspicious:
        print("[✓] No suspicious parent→child edges detected.  Pipeline halted.\n")
        return G, []

    print(f"[!] Suspicious edges detected: {len(suspicious)}\n")
    for parent_g, child_g in suspicious:
        p = _basename(G.nodes[parent_g]["Image"])
        c = _basename(G.nodes[child_g]["Image"])
        print(f"    ⚠  {p} (PID {G.nodes[parent_g]['ProcessId']})  →  "
              f"{c} (PID {G.nodes[child_g]['ProcessId']})")

    # Print the ASCII lineage tree for each unique root
    seen: set[str] = set()
    for parent_g, _ in suspicious:
        chain = trace_chain(G, parent_g)
        root = chain[0]
        if root in seen:
            continue
        seen.add(root)
        print(f"\n  Malicious Process Lineage (root → leaf):\n")
        print_ascii_tree(G, root)

    return G, suspicious


def phase2_triage(G, suspicious: list) -> list[AlertTriageReport]:
    """Generate Pydantic triage reports for each suspicious edge."""
    _phase("PHASE 2 — Structured Pydantic Triage")

    reports: list[AlertTriageReport] = []
    for parent_g, child_g in suspicious:
        chain_guids = trace_chain(G, parent_g)
        chain_nodes = [dict(G.nodes[g]) for g in chain_guids]

        decoded_parts = [
            n.get("DecodedPayload", "")
            for n in chain_nodes if n.get("DecodedPayload")
        ]

        subgraph_data = {
            "parent_image": G.nodes[parent_g]["Image"],
            "child_image":  G.nodes[child_g]["Image"],
            "chain_nodes":  chain_nodes,
            "decoded_command": " | ".join(decoded_parts) if decoded_parts else "",
        }

        report = triage_provenance_chain(subgraph_data)
        reports.append(report)

        print(f"  Alert ID         : {report.alert_id}")
        print(f"  Verdict          : {report.verdict}")
        print(f"  Confidence       : {report.confidence_score:.0%}")
        print(f"  MITRE Technique  : {report.mitre_technique_id} — "
              f"{report.technique_name}")
        print(f"  Explanation      : {report.explanation}")
        print(f"  Decoded Payload  : {report.decoded_command or '(none)'}")
        print(f"  Recommendation   : {report.recommended_action}\n")

    return reports


def phase3_synthesis(report: AlertTriageReport) -> tuple[list[str], list[str]]:
    """Generate Sigma YAML, validate it, compile Splunk SPL + Sentinel KQL."""
    _phase("PHASE 3 — Detection-as-Code Synthesis & SIEM Compilation")

    # Generate Sigma rule
    sigma_yaml = generate_sigma_rule(report)
    os.makedirs(RULES_DIR, exist_ok=True)
    with open(RULE_PATH, "w", encoding="utf-8") as fh:
        fh.write(sigma_yaml)
    print(f"[+] Sigma rule written → {RULE_PATH}\n")

    # Validate + compile
    _, splunk_queries, kql_queries = validate_and_compile(sigma_yaml)

    print(_header("Compiled Splunk SPL Query"))
    for i, q in enumerate(splunk_queries, 1):
        print(f"  [{i}]  {q}\n")

    print(_header("Compiled Microsoft Sentinel KQL Query"))
    for i, q in enumerate(kql_queries, 1):
        print(f"  [{i}]  {q}\n")

    return splunk_queries, kql_queries


def final_summary(
    report: AlertTriageReport,
    elapsed: float,
    splunk_queries: list[str],
    kql_queries: list[str],
) -> None:
    """Print the consolidated execution summary block."""
    width = 72
    print(f"\n{'═' * width}")
    print(f"  {'PASTE ENGINE — FINAL EXECUTION SUMMARY':^{width - 2}}")
    print(f"{'═' * width}")
    print(f"  Execution Time   : {elapsed:.3f}s")
    print(f"  Alert ID         : {report.alert_id}")
    print(f"  Verdict          : {report.verdict}")
    print(f"  Confidence       : {report.confidence_score:.0%}")
    print(f"  MITRE ATT&CK     : {report.mitre_technique_id} — "
          f"{report.technique_name}")
    print(f"  Rule Path        : {RULE_PATH}")
    print(f"  SIEM Outputs     : Splunk SPL ({len(splunk_queries)} query) | "
          f"Sentinel KQL ({len(kql_queries)} query)")
    print(f"{'═' * width}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    default_input = os.path.join(_HERE, "data", "sample_sysmon.json")
    parser = argparse.ArgumentParser(
        prog="paste_engine",
        description="PASTE — Automated Detection Pipeline Driver",
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default=None,
        metavar="FILE",
        help="Positional path to Sysmon JSON log",
    )
    parser.add_argument(
        "--input", "-i",
        default=None,
        dest="input_flag",
        metavar="FILE",
        help=f"Path to Sysmon Event-ID-1 JSON log "
             f"(default: {default_input})",
    )
    args = parser.parse_args()
    # Positional takes priority, then --input, then default
    args.input = args.input_file or args.input_flag or default_input
    return args


def main() -> None:
    args = parse_args()
    t_start = time.perf_counter()

    _banner("PASTE ENGINE  ·  Automated End-to-End Detection Pipeline")
    print(f"\n  Started : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Input   : {args.input}\n")

    # ── Phase 1: Provenance ───────────────────────────────────────────
    G, suspicious = phase1_provenance(args.input)
    if not suspicious:
        print("[~] Pipeline exited cleanly — no malicious chains found.\n")
        return

    # ── Phase 2: Triage ───────────────────────────────────────────────
    reports = phase2_triage(G, suspicious)

    # ── Route by verdict ──────────────────────────────────────────────
    for report in reports:
        if report.verdict == "BENIGN":
            _phase("VERDICT: BENIGN — Event Suppressed")
            print(f"[~] Alert {report.alert_id} classified as BENIGN "
                  f"(confidence {report.confidence_score:.0%}).")
            print("[~] No detection rules generated.  Exiting cleanly.\n")
            continue

        # SUSPICIOUS or MALICIOUS → Phase 3
        splunk_queries, kql_queries = phase3_synthesis(report)
        elapsed = time.perf_counter() - t_start
        final_summary(report, elapsed, splunk_queries, kql_queries)


if __name__ == "__main__":
    main()
