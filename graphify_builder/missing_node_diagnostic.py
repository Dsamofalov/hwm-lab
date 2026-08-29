from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from . import normalize


_STRUCTURAL_PARENT_RELATIONS = frozenset({"contains", "defines", "method"})


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest_records(records: list[dict]) -> str:
    payload = b"\n".join(sorted(_canonical(record) for record in records))
    return hashlib.sha256(payload).hexdigest()


def _presence(values: list[object]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for value in values:
        if value is None:
            counts["null"] += 1
        elif isinstance(value, str):
            counts["empty" if value == "" else "nonempty"] += 1
        else:
            counts[normalize._json_value_type(value)] += 1
    return dict(sorted(counts.items()))


def _value_counts(values: list[object]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for value in values:
        if isinstance(value, str):
            key = value
        else:
            key = f"<{normalize._json_value_type(value)}>:{value!r}"
        counts[key] += 1
    return dict(sorted(counts.items()))


def _suffix(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return Path(value.replace("\\", "/")).suffix.lower()


def _type_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return f"<{normalize._json_value_type(value)}>"


def _relation_context(edge: dict) -> tuple[str, str]:
    relation = edge.get("relation", edge.get("type", edge.get("kind")))
    context = edge.get("context")
    relation_text = relation if isinstance(relation, str) else f"<{normalize._json_value_type(relation)}>"
    context_text = context if isinstance(context, str) else ("" if context is None else f"<{normalize._json_value_type(context)}>")
    return relation_text, context_text


def _triples(counter: Counter[tuple[str, str]]) -> list[list[object]]:
    return [[relation, context, count] for (relation, context), count in sorted(counter.items())]


def _source_type_counts(counter: Counter[tuple[str, str]]) -> list[list[object]]:
    return [[suffix, file_type, count] for (suffix, file_type), count in sorted(counter.items())]


def _source_type_relations(counter: Counter[tuple[str, str, str, str]]) -> list[list[object]]:
    return [
        [suffix, file_type, relation, context, count]
        for (suffix, file_type, relation, context), count in sorted(counter.items())
    ]


def _source_type_parent_kinds(counter: Counter[tuple[str, str, str]]) -> list[list[object]]:
    return [
        [suffix, file_type, parent_kind, count]
        for (suffix, file_type, parent_kind), count in sorted(counter.items())
    ]


def _source_type_degree_pairs(counter: Counter[tuple[str, str, int, int]]) -> list[list[object]]:
    return [
        [suffix, file_type, incoming, outgoing, count]
        for (suffix, file_type, incoming, outgoing), count in sorted(counter.items())
    ]


def _degree_distribution(values: list[int]) -> dict[str, int]:
    return {str(key): value for key, value in sorted(Counter(values).items())}


def _parent_kind(parent: dict | None) -> str:
    if not isinstance(parent, dict):
        return "missing-node"
    for key in ("type", "kind", "node_type"):
        value = parent.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    try:
        known = normalize._missing_discriminator_kind(parent)
    except normalize.GraphOutputError:
        return "missing-discriminator:ambiguous"
    return f"authorized:{known}" if known is not None else "missing-discriminator:unclassified"


def diagnose_missing_discriminator_nodes(graph: object) -> dict | None:
    if not isinstance(graph, dict):
        return None
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return None

    missing: list[dict] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if any(key in node for key in ("type", "kind", "node_type")):
            continue
        try:
            known = normalize._missing_discriminator_kind(node)
        except normalize.GraphOutputError:
            continue
        if known is None:
            missing.append(node)
    if not missing:
        return None

    all_id_groups: Counter[str] = Counter(
        str(node.get("id")) for node in nodes if isinstance(node, dict) and "id" in node
    )
    collision_groups = sum(1 for count in all_id_groups.values() if count > 1)
    missing_ids = {str(node.get("id")) for node in missing}
    node_by_id = {
        str(node.get("id")): node for node in nodes
        if isinstance(node, dict) and "id" in node
    }
    sourced_labels: Counter[str] = Counter(
        node.get("label") for node in nodes
        if isinstance(node, dict)
        and isinstance(node.get("label"), str)
        and isinstance(node.get("source_file"), str)
        and bool(node.get("source_file"))
    )

    families: dict[str, list[dict]] = {}
    for node in missing:
        signature = normalize._missing_discriminator_signature(node)
        families.setdefault(_canonical(signature).decode("utf-8"), []).append(node)

    family_reports: list[dict] = []
    for signature_key in sorted(families):
        family_nodes = families[signature_key]
        signature = json.loads(signature_key)
        ids = {str(node.get("id")) for node in family_nodes}
        family_by_id = {str(node.get("id")): node for node in family_nodes}
        incoming: Counter[tuple[str, str]] = Counter()
        outgoing: Counter[tuple[str, str]] = Counter()
        parent_relations: Counter[tuple[str, str]] = Counter()
        parent_kinds: Counter[str] = Counter()
        incoming_suffixes: Counter[str] = Counter()
        incoming_degree = Counter({node_id: 0 for node_id in ids})
        outgoing_degree = Counter({node_id: 0 for node_id in ids})
        source_type_counts: Counter[tuple[str, str]] = Counter()
        source_type_incoming: Counter[tuple[str, str, str, str]] = Counter()
        source_type_outgoing: Counter[tuple[str, str, str, str]] = Counter()
        source_type_parents: Counter[tuple[str, str, str]] = Counter()

        for node in family_nodes:
            source_type_counts[(_suffix(node.get("source_file")), _type_text(node.get("file_type")))] += 1

        for edge in edges:
            if not isinstance(edge, dict):
                continue
            source = edge.get("source", edge.get("from"))
            target = edge.get("target", edge.get("to"))
            source_id = None if source is None else str(source)
            target_id = None if target is None else str(target)
            relation, context = _relation_context(edge)
            if target_id in ids:
                target_node = family_by_id[target_id]
                target_suffix = _suffix(target_node.get("source_file"))
                target_type = _type_text(target_node.get("file_type"))
                incoming[(relation, context)] += 1
                source_type_incoming[(target_suffix, target_type, relation, context)] += 1
                incoming_degree[target_id] += 1
                suffix = _suffix(edge.get("source_file"))
                if suffix:
                    incoming_suffixes[suffix] += 1
                if relation in _STRUCTURAL_PARENT_RELATIONS:
                    parent_relations[(relation, context)] += 1
                    parent_kind = _parent_kind(node_by_id.get(source_id or ""))
                    parent_kinds[parent_kind] += 1
                    source_type_parents[(target_suffix, target_type, parent_kind)] += 1
            if source_id in ids:
                source_node = family_by_id[source_id]
                source_suffix = _suffix(source_node.get("source_file"))
                source_type = _type_text(source_node.get("file_type"))
                outgoing[(relation, context)] += 1
                source_type_outgoing[(source_suffix, source_type, relation, context)] += 1
                outgoing_degree[source_id] += 1

        source_type_degrees: Counter[tuple[str, str, int, int]] = Counter()
        for node_id, node in family_by_id.items():
            source_type_degrees[
                (
                    _suffix(node.get("source_file")),
                    _type_text(node.get("file_type")),
                    incoming_degree[node_id],
                    outgoing_degree[node_id],
                )
            ] += 1

        same_label_counts: Counter[str] = Counter()
        for node in family_nodes:
            label = node.get("label")
            count = sourced_labels.get(label, 0) if isinstance(label, str) else 0
            if isinstance(node.get("source_file"), str) and node.get("source_file") and count:
                count -= 1
            same_label_counts[str(max(0, count))] += 1

        suffixes = Counter(
            suffix for suffix in (_suffix(node.get("source_file")) for node in family_nodes) if suffix
        )
        family_reports.append({
            "count": len(family_nodes),
            "inventory_sha256": _digest_records(family_nodes),
            "keys": signature["keys"],
            "key_types": signature["key_types"],
            "label_matches_source_basename": signature["label_matches_source_basename"],
            "source_location_shape": signature["source_location_shape"],
            "origin_values": _value_counts([node.get("_origin") for node in family_nodes]),
            "file_type_values": _value_counts([node.get("file_type") for node in family_nodes]),
            "source_file_presence": _presence([node.get("source_file") for node in family_nodes]),
            "source_location_presence": _presence([node.get("source_location") for node in family_nodes]),
            "source_file_suffixes": dict(sorted(suffixes.items())),
            "incoming_relation_context": _triples(incoming),
            "outgoing_relation_context": _triples(outgoing),
            "incoming_degree_distribution": _degree_distribution(list(incoming_degree.values())),
            "outgoing_degree_distribution": _degree_distribution(list(outgoing_degree.values())),
            "structural_parent_relations": _triples(parent_relations),
            "structural_parent_node_kinds": dict(sorted(parent_kinds.items())),
            "incoming_edge_source_suffixes": dict(sorted(incoming_suffixes.items())),
            "same_label_sourced_candidate_counts": dict(sorted(same_label_counts.items())),
            "source_type_counts": _source_type_counts(source_type_counts),
            "source_type_incoming_relation_context": _source_type_relations(source_type_incoming),
            "source_type_outgoing_relation_context": _source_type_relations(source_type_outgoing),
            "source_type_structural_parent_kinds": _source_type_parent_kinds(source_type_parents),
            "source_type_degree_pairs": _source_type_degree_pairs(source_type_degrees),
        })

    return {
        "schema": "hwm-i10-0073-missing-node-diagnostic/v1",
        "total": len(missing),
        "inventory_sha256": _digest_records(missing),
        "stringification_collision_groups": collision_groups,
        "missing_id_count": len(missing_ids),
        "families": family_reports,
    }
