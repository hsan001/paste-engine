#!/usr/bin/env python3
"""
paste_engine – Process & Network Provenance Analyser
====================================================
Reads Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection)
logs, builds a multi-telemetry directed graph with NetworkX, detects suspicious
Living-off-the-Land (LotL) parent→child relationships, and prints the full
causal chain (process lineage + correlated network egress) as an ASCII tree.
"""

import base64
import json
import os
import re
import networkx as nx

# ── Configuration ──────────────────────────────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "sample_sysmon.json")

# Office / productivity binaries that should never spawn shell interpreters
OFFICE_IMAGES = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "msaccess.exe", "mspub.exe",
}

# Shell / LOL interpreters considered suspicious when spawned by Office apps
SUSPICIOUS_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe",
}

# ── Helpers ────────────────────────────────────────────────────────────────

def _basename(path: str) -> str:
    """Return the lower-cased filename from a full image path."""
    return os.path.basename(path).lower()


# Regex: match -e / -enc / -encodedcommand (case-insensitive) followed by
# one or more whitespace chars and then a Base64 chunk (A-Za-z0-9+/=).
_PS_ENC_RE = re.compile(
    r"(?i)(?:-e(?:nc(?:odedcommand)?)?)\s+([A-Za-z0-9+/=]{20,})"
)


def decode_powershell_payload(command_line: str) -> str:
    """
    Detect common PowerShell encoding flags (-e, -enc, -encodedcommand)
    case-insensitively, extract the Base64 chunk, and decode it from
    UTF-16LE (the standard Windows PowerShell encoding).

    Returns the decoded plaintext, or an empty string if no encoded
    payload is found.
    """
    match = _PS_ENC_RE.search(command_line)
    if not match:
        return ""
    b64_chunk = match.group(1)
    try:
        raw_bytes = base64.b64decode(b64_chunk)
        return raw_bytes.decode("utf-16-le")
    except Exception:
        return f"<decode-error: {b64_chunk[:40]}…>"


def load_events(path: str) -> list[dict]:
    """Load and return Sysmon events from a JSON array file."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_graph(events: list[dict]) -> nx.DiGraph:
    """
    Build a multi-telemetry directed graph:
      - Process nodes (Event ID 1): ProcessGuid -> ProcessGuid
      - NetworkSocket nodes (Event ID 3): ProcessGuid -> NetworkSocket
    """
    G = nx.DiGraph()

    # Pass 1: Add nodes
    for ev in events:
        event_id = ev.get("EventID") or ev.get("EventId") or ev.get("event_id")

        if event_id == 1:
            guid = ev["ProcessGuid"]
            decoded = decode_powershell_payload(ev.get("CommandLine", ""))
            G.add_node(
                guid,
                node_type="Process",
                DecodedPayload=decoded,
                **ev
            )
        elif event_id == 3:
            proc_guid = ev.get("ProcessGuid", "")
            dest_ip = ev.get("DestinationIp", "")
            dest_port = str(ev.get("DestinationPort", ""))
            protocol = str(ev.get("Protocol", "TCP")).upper()
            hostname = ev.get("DestinationHostname", "")
            socket_id = f"socket_{proc_guid}_{dest_ip}_{dest_port}"

            G.add_node(
                socket_id,
                node_type="NetworkSocket",
                destination_ip=dest_ip,
                destination_port=dest_port,
                protocol=protocol,
                hostname=hostname,
                **ev
            )

    # Pass 2: Add directed edges
    for ev in events:
        event_id = ev.get("EventID") or ev.get("EventId") or ev.get("event_id")

        if event_id == 1:
            guid = ev["ProcessGuid"]
            parent_guid = ev.get("ParentProcessGuid")
            if parent_guid and parent_guid in G:
                G.add_edge(parent_guid, guid)
        elif event_id == 3:
            proc_guid = ev.get("ProcessGuid", "")
            dest_ip = ev.get("DestinationIp", "")
            dest_port = str(ev.get("DestinationPort", ""))
            socket_id = f"socket_{proc_guid}_{dest_ip}_{dest_port}"
            if proc_guid in G and socket_id in G:
                G.add_edge(proc_guid, socket_id)

    return G


def detect_suspicious_edges(G: nx.DiGraph) -> list[tuple[str, str]]:
    """
    Return a list of (parent_guid, child_guid) edges where an Office
    process directly spawns a shell / LOL binary.
    """
    hits: list[tuple[str, str]] = []
    for parent, child in G.edges():
        if G.nodes[child].get("node_type") == "NetworkSocket":
            continue
        parent_img = _basename(G.nodes[parent].get("Image", ""))
        child_img  = _basename(G.nodes[child].get("Image", ""))
        if parent_img in OFFICE_IMAGES and child_img in SUSPICIOUS_CHILDREN:
            hits.append((parent, child))
    return hits


def trace_chain(G: nx.DiGraph, start_guid: str) -> list[str]:
    """
    Walk from *start_guid* up to the root ancestor, then return the
    full path root → … → leaf for every descendant subtree, including
    child processes and correlated network sockets.
    """
    # Walk UP to root
    root = start_guid
    while True:
        parents = list(G.predecessors(root))
        if not parents:
            break
        root = parents[0]

    # Collect ordered chain
    chain: list[str] = []

    def _dfs(node: str) -> None:
        chain.append(node)
        # Visit NetworkSockets first, then child processes
        children = list(G.successors(node))
        children.sort(key=lambda c: 0 if G.nodes[c].get("node_type") == "NetworkSocket" else 1)
        for child in children:
            _dfs(child)

    _dfs(root)
    return chain


# ── Pretty Printer ─────────────────────────────────────────────────────────

def print_ascii_tree(G: nx.DiGraph, root: str, prefix: str = "",
                     is_last: bool = True, is_root: bool = True) -> None:
    """Recursively print the multi-telemetry process & network tree from *root* downward."""
    node = G.nodes[root]

    if is_root:
        connector = ""
        new_prefix = ""
    else:
        connector  = "└── " if is_last else "├── "
        new_prefix = prefix + ("    " if is_last else "│   ")

    # Render NetworkSocket nodes
    if node.get("node_type") == "NetworkSocket":
        dest_ip = node.get("destination_ip", "")
        dest_port = node.get("destination_port", "")
        proto = node.get("protocol", "TCP").upper()
        hostname = node.get("hostname", "")
        host_str = f" ({hostname})" if hostname else ""
        print(f"{prefix}{connector}[NETWORK EGRESS] {dest_ip}:{dest_port}{host_str} [{proto}]")
        return

    # Render Process nodes
    img_name = _basename(node.get("Image", ""))
    pid      = node.get("ProcessId", 0)
    cmdline  = node.get("CommandLine", "")

    print(f"{prefix}{connector}[{img_name}]  PID: {pid}")
    print(f"{prefix}{'    ' if is_root else new_prefix}  ↳ {cmdline}")

    # Show decoded PowerShell payload if present
    decoded = node.get("DecodedPayload", "")
    if decoded:
        tag_prefix = prefix if is_root else new_prefix
        print(f"{tag_prefix}  [DECODED PAYLOAD]: {decoded}")

    children = list(G.successors(root))
    # Order: NetworkSockets first, then child processes
    children.sort(key=lambda c: 0 if G.nodes[c].get("node_type") == "NetworkSocket" else 1)

    for i, child in enumerate(children):
        last = (i == len(children) - 1)
        print_ascii_tree(G, child, prefix=new_prefix if not is_root else prefix,
                         is_last=last, is_root=False)


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print("  PASTE ENGINE  ·  Process Provenance Analyser")
    print("=" * 72)

    events = load_events(DATA_PATH)
    print(f"\n[*] Loaded {len(events)} Sysmon telemetry records.\n")

    G = build_graph(events)
    print(f"[*] Process graph: {G.number_of_nodes()} nodes, "
          f"{G.number_of_edges()} edges.\n")

    # ── Detection ──────────────────────────────────────────────────────
    suspicious = detect_suspicious_edges(G)
    if not suspicious:
        print("[✓] No suspicious parent→child relationships detected.")
        return

    print(f"[!] Detected {len(suspicious)} suspicious parent→child edge(s):\n")
    for parent_g, child_g in suspicious:
        p_img = _basename(G.nodes[parent_g]["Image"])
        c_img = _basename(G.nodes[child_g]["Image"])
        print(f"    ⚠  {p_img} (PID {G.nodes[parent_g]['ProcessId']})  →  "
              f"{c_img} (PID {G.nodes[child_g]['ProcessId']})")

    # ── Full Causal Chain ──────────────────────────────────────────────
    seen_roots: set[str] = set()
    for parent_g, _ in suspicious:
        chain = trace_chain(G, parent_g)
        root  = chain[0]
        if root in seen_roots:
            continue
        seen_roots.add(root)

        print("\n" + "─" * 72)
        print("  MALICIOUS PROCESS LINEAGE  (root → leaf)")
        print("─" * 72 + "\n")
        print_ascii_tree(G, root)

    print("\n" + "=" * 72)
    print("  Analysis complete.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
