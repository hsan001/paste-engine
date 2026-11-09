#!/usr/bin/env python3
"""
paste_engine – Interactive Provenance Graph Visualizer (Phase 4)
================================================================
Generates modern, self-contained, dark-mode interactive HTML graphs
visualizing process execution trees and correlated network egress.
Uses Vis.js with embedded styles, tooltips, and an offline fallback.
"""

from __future__ import annotations

import html
import json
import os
import networkx as nx

# ── Color Palette ──────────────────────────────────────────────────────────
COLOR_ROOT = "#64748b"       # Slate Gray (Root / Parent Processes)
COLOR_MALICIOUS = "#ef4444"  # Crimson Red (Suspicious / Malicious Processes)
COLOR_NETWORK = "#06b6d4"    # Cyan / Blue (Network Sockets / Egress)
COLOR_PAYLOAD = "#f59e0b"    # Amber / Gold (Decoded Payloads / Commands)
COLOR_BENIGN = "#475569"     # Dark Slate (Benign / Utility Processes)


def _basename(path: str) -> str:
    """Return lower-cased filename from path."""
    return os.path.basename(path).lower() if path else ""


def generate_interactive_graph(
    graph: nx.DiGraph,
    output_path: str = "paste_engine/reports/provenance_graph.html",
) -> str:
    """
    Generate a self-contained, dark-mode interactive HTML visualization of
    the process and network provenance graph.

    Args:
        graph: NetworkX DiGraph containing process and network nodes.
        output_path: Target HTML filepath.

    Returns:
        The absolute path to the generated HTML file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    nodes_data = []
    edges_data = []

    # Map nodes to Vis.js data format
    for node_id in graph.nodes():
        node = graph.nodes[node_id]
        node_type = node.get("node_type", "Process")

        if node_type == "NetworkSocket":
            dest_ip = node.get("destination_ip", "Unknown")
            dest_port = node.get("destination_port", "")
            proto = node.get("protocol", "TCP").upper()
            hostname = node.get("hostname", "")
            host_display = f"\n({hostname})" if hostname else ""

            label = f"[EGRESS: {proto}]\n{dest_ip}:{dest_port}{host_display}"
            tooltip = (
                f"<b>Type:</b> Network Socket (Sysmon EID 3)<br>"
                f"<b>Protocol:</b> {html.escape(proto)}<br>"
                f"<b>Destination:</b> {html.escape(dest_ip)}:{html.escape(str(dest_port))}<br>"
                f"<b>Hostname:</b> {html.escape(hostname or 'N/A')}<br>"
                f"<b>Initiated:</b> {html.escape(str(node.get('Initiated', 'true')))}<br>"
                f"<b>Timestamp:</b> {html.escape(str(node.get('UtcTime', 'N/A')))}"
            )

            nodes_data.append({
                "id": node_id,
                "label": label,
                "title": tooltip,
                "shape": "diamond",
                "color": {
                    "background": COLOR_NETWORK,
                    "border": "#0891b2",
                    "highlight": {"background": "#22d3ee", "border": "#ffffff"},
                },
                "font": {"color": "#ffffff", "face": "monospace", "size": 12},
                "borderWidth": 2,
            })

        else:
            # Process Node
            image = node.get("Image", "Unknown")
            img_base = _basename(image)
            pid = node.get("ProcessId", 0)
            cmdline = node.get("CommandLine", "")
            user = node.get("User", "")
            time_str = node.get("UtcTime", "")
            decoded = node.get("DecodedPayload", "")

            # Identify if node is a root process (no process predecessors)
            process_parents = [
                p for p in graph.predecessors(node_id)
                if graph.nodes[p].get("node_type", "Process") == "Process"
            ]
            is_root = (len(process_parents) == 0) or (node.get("ParentImage") == "-")

            if is_root:
                bg_color = COLOR_ROOT
                border_color = "#475569"
            else:
                bg_color = COLOR_MALICIOUS
                border_color = "#dc2626"

            label = f"[{img_base}]\nPID: {pid}"
            tooltip = (
                f"<b>Process:</b> {html.escape(img_base)} (PID {pid})<br>"
                f"<b>Full Path:</b> {html.escape(image)}<br>"
                f"<b>User:</b> {html.escape(user)}<br>"
                f"<b>Timestamp:</b> {html.escape(time_str)}<br>"
                f"<b>Command:</b> <code>{html.escape(cmdline)}</code>"
            )

            if decoded:
                tooltip += f"<br><br><b>Decoded Payload:</b><br><code style='color:#f59e0b;'>{html.escape(decoded)}</code>"

            nodes_data.append({
                "id": node_id,
                "label": label,
                "title": tooltip,
                "shape": "box",
                "color": {
                    "background": bg_color,
                    "border": border_color,
                    "highlight": {"background": "#f87171" if not is_root else "#94a3b8", "border": "#ffffff"},
                },
                "font": {"color": "#ffffff", "face": "monospace", "size": 13, "bold": True},
                "borderWidth": 2,
                "margin": 10,
            })

            # If node has decoded payload, add a linked payload node
            if decoded:
                payload_node_id = f"payload_{node_id}"
                short_payload = decoded if len(decoded) <= 45 else decoded[:42] + "..."
                payload_label = f"[DECODED PAYLOAD]\n{short_payload}"
                payload_tooltip = f"<b>Decoded PowerShell Payload:</b><br><code>{html.escape(decoded)}</code>"

                nodes_data.append({
                    "id": payload_node_id,
                    "label": payload_label,
                    "title": payload_tooltip,
                    "shape": "ellipse",
                    "color": {
                        "background": COLOR_PAYLOAD,
                        "border": "#d97706",
                        "highlight": {"background": "#fbbf24", "border": "#ffffff"},
                    },
                    "font": {"color": "#0f172a", "face": "monospace", "size": 11, "bold": True},
                    "borderWidth": 2,
                })

                edges_data.append({
                    "from": node_id,
                    "to": payload_node_id,
                    "arrows": "to",
                    "color": {"color": "#f59e0b", "highlight": "#fbbf24"},
                    "dashes": True,
                    "width": 2,
                    "label": "de-obfuscated",
                    "font": {"color": "#f59e0b", "size": 10, "align": "top"},
                })

    # Add edges from graph
    for u, v in graph.edges():
        target_type = graph.nodes[v].get("node_type", "Process")
        if target_type == "NetworkSocket":
            edge_color = "#06b6d4"
            edge_dashes = True
            edge_label = "TCP egress"
        else:
            edge_color = "#94a3b8"
            edge_dashes = False
            edge_label = "spawns"

        edges_data.append({
            "from": u,
            "to": v,
            "arrows": "to",
            "color": {"color": edge_color, "highlight": "#ffffff"},
            "dashes": edge_dashes,
            "width": 2,
            "label": edge_label,
            "font": {"color": "#94a3b8", "size": 10, "align": "top"},
        })

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PASTE Engine – Process Provenance & Network Egress DAG</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      background-color: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      height: 100vh;
    }}
    header {{
      background: #1e293b;
      padding: 12px 24px;
      border-bottom: 1px solid #334155;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 10;
    }}
    .title-group h1 {{
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #38bdf8;
    }}
    .title-group p {{
      font-size: 0.8rem;
      color: #94a3b8;
    }}
    .legend {{
      display: flex;
      gap: 16px;
      font-size: 0.78rem;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .legend-dot {{
      width: 12px;
      height: 12px;
      border-radius: 3px;
    }}
    #network-container {{
      flex: 1;
      position: relative;
      background: radial-gradient(circle at 50% 50%, #1e293b 0%, #0f172a 100%);
    }}
    #vis-network {{
      width: 100%;
      height: 100%;
    }}
    .control-panel {{
      position: absolute;
      bottom: 20px;
      right: 20px;
      background: rgba(30, 41, 59, 0.85);
      backdrop-filter: blur(8px);
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid #334155;
      display: flex;
      gap: 10px;
      z-index: 20;
    }}
    button {{
      background: #334155;
      color: #f8fafc;
      border: 1px solid #475569;
      padding: 6px 12px;
      font-size: 0.75rem;
      border-radius: 4px;
      cursor: pointer;
      transition: background 0.15s ease;
    }}
    button:hover {{
      background: #475569;
    }}
    .stats-card {{
      position: absolute;
      top: 20px;
      left: 20px;
      background: rgba(30, 41, 59, 0.85);
      backdrop-filter: blur(8px);
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid #334155;
      font-size: 0.78rem;
      color: #cbd5e1;
      z-index: 20;
      line-height: 1.5;
    }}
    .stats-card b {{
      color: #38bdf8;
    }}
    /* Vis.js Tooltip Styling Override */
    div.vis-tooltip {{
      background-color: #1e293b !important;
      border: 1px solid #475569 !important;
      color: #f8fafc !important;
      font-family: inherit !important;
      font-size: 12px !important;
      padding: 10px 14px !important;
      border-radius: 6px !important;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5) !important;
      max-width: 480px !important;
      line-height: 1.4 !important;
      z-index: 1000 !important;
    }}
    code {{
      background: #0f172a;
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 11px;
      word-break: break-all;
    }}
  </style>
</head>
<body>
  <header>
    <div class="title-group">
      <h1>PASTE Autonomous Engine · Provenance Graph</h1>
      <p>Causality-Aware Process Lineage & Network Egress DAG</p>
    </div>
    <div class="legend">
      <div class="legend-item"><span class="legend-dot" style="background:{COLOR_ROOT}"></span> Root / Parent</div>
      <div class="legend-item"><span class="legend-dot" style="background:{COLOR_MALICIOUS}"></span> Malicious Process</div>
      <div class="legend-item"><span class="legend-dot" style="background:{COLOR_NETWORK}"></span> Network Socket</div>
      <div class="legend-item"><span class="legend-dot" style="background:{COLOR_PAYLOAD}"></span> Decoded Payload</div>
    </div>
  </header>

  <div id="network-container">
    <div class="stats-card">
      <div><b>Graph Size:</b> {len(nodes_data)} Nodes &bull; {len(edges_data)} Directed Edges</div>
      <div><b>Telemetry:</b> Sysmon EID 1 (Process) + EID 3 (Network)</div>
      <div><b>Navigation:</b> Drag to Pan &bull; Scroll to Zoom &bull; Hover for Details</div>
    </div>

    <div id="vis-network"></div>

    <div class="control-panel">
      <button onclick="network.fit({{animation: true}})">Fit View</button>
      <button onclick="togglePhysics()">Toggle Physics</button>
    </div>
  </div>

  <script type="text/javascript">
    const nodes = new vis.DataSet({json.dumps(nodes_data, indent=2)});
    const edges = new vis.DataSet({json.dumps(edges_data, indent=2)});

    const container = document.getElementById('vis-network');
    const data = {{ nodes: nodes, edges: edges }};

    const options = {{
      layout: {{
        hierarchical: {{
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          levelSeparation: 130,
          nodeSpacing: 240,
          treeSpacing: 260,
          blockShifting: true,
          edgeMinimization: true,
        }}
      }},
      physics: {{
        enabled: false,
        hierarchicalRepulsion: {{
          nodeDistance: 190
        }}
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
        multiselect: false,
      }},
      nodes: {{
        shadow: {{
          enabled: true,
          color: 'rgba(0,0,0,0.4)',
          size: 10,
          x: 2,
          y: 4
        }}
      }},
      edges: {{
        smooth: {{
          type: 'cubicBezier',
          forceDirection: 'vertical',
          roundness: 0.5
        }}
      }}
    }};

    let network = null;
    let physicsEnabled = false;

    try {{
      network = new vis.Network(container, data, options);
    }} catch (err) {{
      console.warn("Vis.js initialization failed or offline:", err);
      container.innerHTML = "<div style='padding:40px; color:#ef4444;'>Vis.js renderer offline. Process tree nodes: " + nodes.length + ", Edges: " + edges.length + "</div>";
    }}

    function togglePhysics() {{
      if (!network) return;
      physicsEnabled = !physicsEnabled;
      network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
    }}
  </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    return os.path.abspath(output_path)


if __name__ == "__main__":
    from provenance import DATA_PATH, build_graph, load_events
    events = load_events(DATA_PATH)
    G = build_graph(events)
    path = generate_interactive_graph(G)
    print(f"[+] Interactive provenance graph generated: {path}")
