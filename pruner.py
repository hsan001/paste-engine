#!/usr/bin/env python3
"""
paste_engine – Bidirectional Subgraph Pruner (Phase 5)
======================================================
Prunes large, noisy enterprise process & network DAGs down to their minimal
causal core. Traverses backward to identify root execution ancestors and
forward to capture all descendant processes and egress network sockets.
"""

from __future__ import annotations

import networkx as nx


def extract_causal_subgraph(
    full_graph: nx.DiGraph,
    pivot_node_id: str,
) -> nx.DiGraph:
    """
    Extract the minimal induced causal subgraph containing the primary ancestor,
    the pivot node, and all descendant processes and network sockets.

    Args:
        full_graph: The complete enterprise provenance DAG containing noise.
        pivot_node_id: The node identifier of the detected suspicious activity.

    Returns:
        A new NetworkX DiGraph containing only the causal lineage.
    """
    if pivot_node_id not in full_graph:
        return full_graph.copy()

    # 1. Backward traversal: find all ancestors of the pivot node
    ancestor_nodes = nx.ancestors(full_graph, pivot_node_id)
    causal_nodes = set(ancestor_nodes)
    causal_nodes.add(pivot_node_id)

    # 2. Forward traversal: find all descendants of all ancestors and the pivot
    seeds = list(causal_nodes)
    for seed in seeds:
        descendants = nx.descendants(full_graph, seed)
        causal_nodes.update(descendants)

    # 3. Create induced subgraph
    pruned_subgraph = full_graph.subgraph(causal_nodes).copy()

    # 4. Compute and log compression metrics
    total_nodes = full_graph.number_of_nodes()
    causal_count = pruned_subgraph.number_of_nodes()
    noise_reduction = (
        ((total_nodes - causal_count) / total_nodes * 100.0)
        if total_nodes > 0 else 0.0
    )

    metrics = {
        "total_nodes": total_nodes,
        "causal_nodes": causal_count,
        "pruned_nodes": total_nodes - causal_count,
        "noise_reduction_pct": noise_reduction,
    }
    pruned_subgraph.graph["pruning_metrics"] = metrics

    print(
        f"[*] Graph pruned from {total_nodes} total nodes to {causal_count} causal nodes "
        f"({noise_reduction:.1f}% noise reduction)"
    )

    return pruned_subgraph


if __name__ == "__main__":
    from provenance import DATA_PATH, build_graph, detect_suspicious_edges, load_events
    events = load_events(DATA_PATH)
    G = build_graph(events)
    suspicious = detect_suspicious_edges(G)
    if suspicious:
        pivot = suspicious[0][1]
        sub = extract_causal_subgraph(G, pivot)
        print(f"Causal nodes: {list(sub.nodes())}")
