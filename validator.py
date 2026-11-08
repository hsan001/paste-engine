#!/usr/bin/env python3
"""
paste_engine – Sigma Rule Validator & SIEM Compiler (Phase 3)
=============================================================
Reads the auto-generated Sigma YAML rule, validates it with pySigma,
and compiles it into Splunk SPL and Microsoft Sentinel KQL queries.
"""

from __future__ import annotations

import os
import sys
import textwrap

# ── PyYAML C-extension shim ───────────────────────────────────────────────
# pySigma references yaml.CSafeLoader / yaml.CDumper, which are only
# available when PyYAML was built with the C LibYAML extension.  On systems
# where the C extension is absent (pure-Python wheel), we alias the
# pure-Python equivalents so the library can still load.
import yaml

if not hasattr(yaml, "CSafeLoader"):
    yaml.CSafeLoader = yaml.SafeLoader  # type: ignore[attr-defined]
if not hasattr(yaml, "CDumper"):
    yaml.CDumper = yaml.Dumper  # type: ignore[attr-defined]

# ── pySigma imports (after shim) ──────────────────────────────────────────
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.microsoft365defender import KustoBackend as M365DBackend

# ── Paths ─────────────────────────────────────────────────────────────────
RULE_PATH = os.path.join(
    os.path.dirname(__file__), "rules", "sigma_auto_rule.yml"
)


def load_rule(path: str) -> str:
    """Read the raw YAML rule from disk."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def validate_and_compile(raw_yaml: str) -> tuple[
    SigmaCollection, list[str], list[str]
]:
    """
    Parse / validate the YAML into a ``SigmaCollection``, then compile it
    with the Splunk and Microsoft 365 Defender (Kusto / KQL) backends.

    Returns (collection, splunk_queries, kql_queries).
    """
    collection = SigmaCollection.from_yaml(raw_yaml)
    print(f"[✓] Sigma YAML parsed successfully  "
          f"({len(collection)} rule(s) loaded).\n")

    # ── Splunk SPL ─────────────────────────────────────────────────────
    splunk_backend = SplunkBackend()
    splunk_queries: list[str] = []
    for rule in collection:
        splunk_queries.extend(splunk_backend.convert_rule(rule))

    # ── Microsoft Sentinel KQL (Kusto) ─────────────────────────────────
    kql_backend = M365DBackend()
    kql_queries: list[str] = []
    for rule in collection:
        kql_queries.extend(kql_backend.convert_rule(rule))

    return collection, splunk_queries, kql_queries


def _header(title: str) -> str:
    return f"\n{'─' * 72}\n  {title}\n{'─' * 72}\n"


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  PASTE ENGINE  ·  Sigma Rule Validator & SIEM Compiler")
    print("=" * 72)

    if not os.path.isfile(RULE_PATH):
        print(f"\n[!] Rule file not found: {RULE_PATH}")
        print("    Run synthesizer.py first to generate the rule.\n")
        sys.exit(1)

    raw_yaml = load_rule(RULE_PATH)

    # ── Display raw Sigma YAML ─────────────────────────────────────────
    print(_header("Raw Sigma YAML"))
    print(raw_yaml)

    # ── Validate & compile ─────────────────────────────────────────────
    collection, splunk_queries, kql_queries = validate_and_compile(raw_yaml)

    # ── Splunk SPL output ──────────────────────────────────────────────
    print(_header("Compiled Splunk SPL Query"))
    for i, q in enumerate(splunk_queries, 1):
        print(f"  [{i}]  {q}\n")

    # ── Sentinel KQL output ────────────────────────────────────────────
    print(_header("Compiled Microsoft Sentinel KQL Query"))
    for i, q in enumerate(kql_queries, 1):
        print(f"  [{i}]  {q}\n")

    # ── Summary ────────────────────────────────────────────────────────
    rule = collection[0]
    print("=" * 72)
    print(f"  Validation: PASSED")
    print(f"  Rule title: {rule.title}")
    print(f"  Rule ID:    {rule.id}")
    print(f"  Level:      {rule.level}")
    print(f"  Backends:   Splunk SPL ✓  |  Microsoft Sentinel KQL ✓")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
