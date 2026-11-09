#!/usr/bin/env python3
"""
paste_engine – Automated End-to-End Detection Pipeline Driver
=============================================================
Ties together every PASTE phase in a single CLI entrypoint:

  Phase 1 – Multi-telemetry provenance graph reconstruction + PowerShell de-obfuscation
  Phase 2 – Bidirectional causal subgraph pruning + OSINT threat intelligence enrichment
  Phase 3 – Structured Pydantic dual-mode triage (AlertTriageReport)
  Phase 4 – Detection-as-Code synthesis + SIEM compilation (Splunk SPL & Sentinel KQL)
  Phase 5 – Interactive provenance visualization + automated IR incident reporting

Usage:
    python paste_engine/main.py [--input <path/to/sysmon.json>]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any

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
from pruner import extract_causal_subgraph
from enricher import enrich_iocs, format_threat_intel_summary
from triage import (
    AlertTriageReport,
    get_triage_mode,
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
from visualizer import generate_interactive_graph
from reporter import generate_incident_brief

# ── Output paths ───────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(_HERE, "reports")
GRAPH_HTML_PATH = os.path.join(REPORTS_DIR, "provenance_graph.html")


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
    print(f"[*] Events loaded : {len(events)} Sysmon Event-ID-1/3 record(s)\n")

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


def phase2_pruning_and_enrichment(G, suspicious: list):
    """
    Phase 2: Bidirectional Subgraph Pruning & OSINT Threat Intel Enrichment.
    Prunes the provenance graph down to its minimal causal DAG and enriches
    discovered network indicators with OSINT threat intelligence.
    """
    _phase("PHASE 2 — Causal Subgraph Pruning & OSINT Threat Intel Enrichment")
    pruned_results = []

    for parent_g, child_g in suspicious:
        # 1. Prune graph around suspicious child pivot
        causal_G = extract_causal_subgraph(G, child_g)
        pruning_metrics = causal_G.graph.get("pruning_metrics", {})

        # 2. Extract network indicators from causal subgraph
        network_indicators: list[str] = []
        for n_id, n_data in causal_G.nodes(data=True):
            if n_data.get("node_type") == "NetworkSocket":
                dest_ip = n_data.get("destination_ip")
                hostname = n_data.get("hostname")
                if dest_ip and dest_ip not in network_indicators:
                    network_indicators.append(dest_ip)
                if hostname and hostname not in network_indicators:
                    network_indicators.append(hostname)

        # 3. Enrich IP indicators with OSINT
        raw_ips = [i for i in network_indicators if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", i)]
        threat_intel = enrich_iocs(raw_ips)
        if threat_intel:
            print(f"[*] Threat Intel Enriched: {format_threat_intel_summary(threat_intel)}\n")

        # 4. Extract causal process chain nodes
        chain_guids = trace_chain(causal_G, parent_g)
        chain_nodes = [dict(causal_G.nodes[g]) for g in chain_guids]

        decoded_parts = [
            n.get("DecodedPayload", "")
            for n in chain_nodes if n.get("DecodedPayload")
        ]

        subgraph_data = {
            "parent_image": causal_G.nodes[parent_g]["Image"],
            "child_image":  causal_G.nodes[child_g]["Image"],
            "chain_nodes":  chain_nodes,
            "decoded_command": " | ".join(decoded_parts) if decoded_parts else "",
            "network_indicators": network_indicators,
            "threat_intel": threat_intel,
        }

        pruned_results.append((parent_g, child_g, causal_G, subgraph_data, pruning_metrics))

    return pruned_results


def phase3_triage(pruned_results: list) -> list[tuple[AlertTriageReport, dict, Any, dict]]:
    """Generate Pydantic triage reports for each pruned causal subgraph."""
    _phase("PHASE 3 — Structured Pydantic Triage (Dual-Mode)")

    results: list[tuple[AlertTriageReport, dict, Any, dict]] = []
    for parent_g, child_g, causal_G, subgraph_data, pruning_metrics in pruned_results:
        report = triage_provenance_chain(subgraph_data)
        results.append((report, subgraph_data, causal_G, pruning_metrics))

        print(f"  Alert ID         : {report.alert_id}")
        print(f"  Verdict          : {report.verdict}")
        print(f"  Confidence       : {report.confidence_score:.0%}")
        print(f"  MITRE Technique  : {report.mitre_technique_id} — "
              f"{report.technique_name}")
        print(f"  Explanation      : {report.explanation}")
        print(f"  Decoded Payload  : {report.decoded_command or '(none)'}")
        if report.network_indicators:
            print(f"  Network Egress   : {', '.join(report.network_indicators)}")
        if report.threat_intel:
            print(f"  Threat Intel     : {format_threat_intel_summary(report.threat_intel)}")
        print(f"  Recommendation   : {report.recommended_action}\n")

    return results


def phase4_synthesis(report: AlertTriageReport) -> tuple[list[str], list[str]]:
    """Generate Sigma YAML, validate it, compile Splunk SPL + Sentinel KQL."""
    _phase("PHASE 4 — Detection-as-Code Synthesis & SIEM Compilation")

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
    graph_path: str | None = None,
    brief_path: str | None = None,
    pruning_metrics: dict | None = None,
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
    if pruning_metrics:
        total = pruning_metrics.get("total_nodes", 0)
        causal = pruning_metrics.get("causal_nodes", 0)
        reduc = pruning_metrics.get("noise_reduction_pct", 0.0)
        print(f"  Graph Pruning    : {total} total nodes → {causal} causal nodes "
              f"({reduc:.1f}% noise reduction)")
    if report.network_indicators:
        print(f"  Network Egress   : {', '.join(report.network_indicators)}")
    if report.threat_intel:
        for ip, intel in report.threat_intel.items():
            cls_name = intel.get("threat_classification", "Unknown")
            abuse = intel.get("abuse_confidence_score", 0)
            country = intel.get("country", "")
            print(f"  OSINT Intel      : {ip} [{country}] → {cls_name} (Abuse: {abuse}%)")
    print(f"  Rule Path        : {RULE_PATH}")
    if graph_path:
        rel_graph = os.path.relpath(graph_path).replace("\\", "/")
        print(f"  [Visual Graph]  : {rel_graph}")
    if brief_path:
        rel_brief = os.path.relpath(brief_path).replace("\\", "/")
        print(f"  [Incident Brief]: {rel_brief}")
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
        help=f"Path to Sysmon Event-ID-1/3 JSON log "
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
    print(f"  Input   : {args.input}")
    print(f"  [PASTE Core] Engine Mode: {get_triage_mode()}\n")

    # ── Phase 1: Provenance ───────────────────────────────────────────
    G, suspicious = phase1_provenance(args.input)
    if not suspicious:
        print("[~] Pipeline exited cleanly — no malicious chains found.\n")
        return

    # ── Phase 2: Pruning & OSINT Enrichment ───────────────────────────
    pruned_results = phase2_pruning_and_enrichment(G, suspicious)

    # ── Phase 3: Triage ───────────────────────────────────────────────
    triage_results = phase3_triage(pruned_results)

    # ── Route by verdict ──────────────────────────────────────────────
    for report, subgraph_data, causal_G, pruning_metrics in triage_results:
        if report.verdict == "BENIGN":
            _phase("VERDICT: BENIGN — Event Suppressed")
            print(f"[~] Alert {report.alert_id} classified as BENIGN "
                  f"(confidence {report.confidence_score:.0%}).")
            print("[~] No detection rules generated.  Exiting cleanly.\n")
            continue

        # SUSPICIOUS or MALICIOUS → Phase 4: Synthesis
        splunk_queries, kql_queries = phase4_synthesis(report)

        graph_path = None
        brief_path = None

        if report.verdict == "MALICIOUS":
            _phase("PHASE 5 — Incident Reporting & Provenance Visualization")
            os.makedirs(REPORTS_DIR, exist_ok=True)
            graph_path = generate_interactive_graph(causal_G, output_path=GRAPH_HTML_PATH)
            print(f"[+] Interactive provenance graph written → {graph_path}")

            brief_path = generate_incident_brief(
                triage_report=report,
                graph_data=subgraph_data,
                sigma_rule_path=RULE_PATH,
                splunk_query=splunk_queries,
                kql_query=kql_queries,
                output_dir=REPORTS_DIR,
            )
            print(f"[+] Incident response brief written → {brief_path}\n")

        elapsed = time.perf_counter() - t_start
        final_summary(report, elapsed, splunk_queries, kql_queries, graph_path, brief_path, pruning_metrics)


if __name__ == "__main__":
    main()
