from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path, PurePosixPath

from .policy import (
    CANONICALIZATION,
    GRAPHIFY_PACKAGE,
    GRAPHIFY_VERSION,
    GRAPHIFY_WHEEL_SHA256,
    MAX_SNAPSHOT_BYTES,
    PRODUCT_REPOSITORY,
    RUNTIME_VERSION,
    UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY,
    UPSTREAM_TAG,
)


class GraphOutputError(RuntimeError):
    pass


class SnapshotSchemaError(RuntimeError):
    pass


class OversizedSnapshotError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _text(value: object, *, field: str, max_len: int, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise GraphOutputError(f"{field} must be text")
    value = unicodedata.normalize("NFC", value)
    if nonempty and not value:
        raise GraphOutputError(f"{field} is empty")
    if len(value) > max_len:
        raise GraphOutputError(f"{field} is too long")
    return value


def normalize_path(value: object, product_root: Path) -> str:
    raw = _text(value, field="source_file", max_len=16384, nonempty=True).replace("\\", "/")
    path = Path(raw)
    if path.is_absolute():
        try:
            raw = path.resolve(strict=False).relative_to(product_root.resolve(strict=True)).as_posix()
        except ValueError as exc:
            raise GraphOutputError("absolute/host-specific source path outside product root") from exc
    pure = PurePosixPath(unicodedata.normalize("NFC", raw))
    if pure.is_absolute() or not pure.parts:
        raise GraphOutputError("source path must be repository-relative")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise GraphOutputError("source path contains current/parent segment")
    normalized = pure.as_posix()
    if normalized.startswith("graphify-out/") or normalized == "graphify-out":
        raise GraphOutputError("Graphify output cannot be a product source path")
    if len(normalized) > 4096:
        raise GraphOutputError("source path exceeds schema limit")
    return normalized


def _lines(node: dict) -> tuple[int, int]:
    start, end = node.get("start_line"), node.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and start >= 1 and end >= start:
        return start, end
    loc = node.get("source_location")
    if isinstance(loc, str):
        m = re.fullmatch(r"L(\d+)(?:-L?(\d+))?", loc.strip())
        if m:
            start = int(m.group(1)); end = int(m.group(2) or m.group(1))
            if start >= 1 and end >= start:
                return start, end
    line = node.get("line")
    if isinstance(line, int) and line >= 1:
        return line, line
    raise GraphOutputError("node lacks deterministic source line range")


_DIAGNOSTIC_FIELDS = ("id", "label", "source_file", "source_location", "file_type")
_DIAGNOSTIC_VALUE_LIMIT = 64
_DIAGNOSTIC_REPRESENTATIVE_LIMIT = 3
_DIAGNOSTIC_DETAIL_LIMIT = 4000


_EDGE_DIAGNOSTIC_REPRESENTATIVE_LIMIT = 3
_EDGE_DIAGNOSTIC_DETAIL_LIMIT = 4000
_EDGE_DISCRIMINATOR_FIELDS = ("relation", "type", "kind")
_SENSITIVE_DIAGNOSTIC_TEXT = re.compile(
    r"(?i)(?:secret|token|password|credential|authorization|bearer|api[_-]?key)"
)


def _edge_diagnostic_text(value: str) -> str:
    value = unicodedata.normalize("NFC", value)
    value = "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in value)
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    normalized_path = value.replace("\\", "/")
    if normalized_path.startswith("/") or re.match(r"^[A-Za-z]:/", normalized_path):
        return "redacted-absolute-path~" + digest
    if _SENSITIVE_DIAGNOSTIC_TEXT.search(value):
        return "redacted-sensitive~" + digest
    if len(value) <= _DIAGNOSTIC_VALUE_LIMIT:
        return value
    keep = _DIAGNOSTIC_VALUE_LIMIT - len(digest) - 2
    return value[:keep] + "~" + digest


def _edge_endpoint_representative(value: object, *, raw_node_ids: set[str],
                                  upstream_to_hwm: dict[str, str]) -> dict:
    stringified = str(value)
    return {
        "type": _json_value_type(value),
        "stringified": _edge_diagnostic_text(stringified),
        "in_raw_node_ids": stringified in raw_node_ids,
        "in_upstream_to_hwm": stringified in upstream_to_hwm,
    }


def _edge_discriminator_shape(edge: dict) -> dict:
    return {
        field: (
            {"present": True, "type": _json_value_type(edge[field])}
            if field in edge else {"present": False, "type": "missing"}
        )
        for field in _EDGE_DISCRIMINATOR_FIELDS
    }


def _selected_edge_endpoint(edge: dict, primary: str, fallback: str) -> tuple[str, object]:
    key = primary if primary in edge else fallback
    return key, edge.get(primary, edge.get(fallback))


def _raw_node_id_index(nodes: list) -> set[str]:
    groups: dict[str, dict] = {}
    for node in nodes:
        raw_id = node["id"]
        stringified = str(raw_id)
        representative = {
            "type": _json_value_type(raw_id),
            "stringified": _edge_diagnostic_text(stringified),
        }
        representative_key = canonical_json(representative).decode("utf-8")
        group = groups.setdefault(stringified, {"count": 0, "representatives": {}})
        group["count"] += 1
        group["representatives"][representative_key] = representative
    collisions = []
    for stringified in sorted(groups):
        group = groups[stringified]
        if group["count"] <= 1:
            continue
        representative_keys = sorted(group["representatives"])
        collisions.append({
            "count": group["count"],
            "representative_variants": len(representative_keys),
            "representatives": [
                group["representatives"][key]
                for key in representative_keys[:_EDGE_DIAGNOSTIC_REPRESENTATIVE_LIMIT]
            ],
        })
    if collisions:
        summary = {
            "raw_node_count": len(nodes),
            "stringified_raw_node_id_count": len(groups),
            "collision_group_count": len(collisions),
            "collision_node_count": sum(group["count"] for group in collisions),
            "groups": collisions,
        }
        detail = "raw node id stringification collision inventory: " + canonical_json(summary).decode("utf-8")
        if len(detail) > _EDGE_DIAGNOSTIC_DETAIL_LIMIT:
            raise GraphOutputError("raw node id stringification collision inventory exceeds bounded detail capacity")
        raise GraphOutputError(detail)
    return set(groups)


def _dangling_edge_inventory(edges: list, *, raw_node_count: int,
                             raw_node_ids: set[str],
                             upstream_to_hwm: dict[str, str]) -> dict:
    groups: dict[str, dict] = {}
    source_only = target_only = both = unresolved_total = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source_key, source = _selected_edge_endpoint(edge, "source", "from")
        target_key, target = _selected_edge_endpoint(edge, "target", "to")
        if source is None or target is None:
            continue
        source_text, target_text = str(source), str(target)
        source_resolved = source_text in upstream_to_hwm
        target_resolved = target_text in upstream_to_hwm
        if source_resolved and target_resolved:
            continue
        unresolved_total += 1
        if not source_resolved and not target_resolved:
            both += 1
        elif not source_resolved:
            source_only += 1
        else:
            target_only += 1
        keys = sorted(edge)
        signature = {
            "keys": keys,
            "key_types": {key: _json_value_type(edge[key]) for key in keys},
            "selected_source_key": source_key,
            "selected_target_key": target_key,
            "selected_source_type": _json_value_type(source),
            "selected_target_type": _json_value_type(target),
            "source_in_raw_node_ids": source_text in raw_node_ids,
            "target_in_raw_node_ids": target_text in raw_node_ids,
            "source_in_upstream_to_hwm": source_resolved,
            "target_in_upstream_to_hwm": target_resolved,
            "edge_discriminators": _edge_discriminator_shape(edge),
        }
        signature_key = canonical_json(signature).decode("utf-8")
        representative = {
            "source": _edge_endpoint_representative(
                source, raw_node_ids=raw_node_ids, upstream_to_hwm=upstream_to_hwm
            ),
            "target": _edge_endpoint_representative(
                target, raw_node_ids=raw_node_ids, upstream_to_hwm=upstream_to_hwm
            ),
        }
        representative_key = canonical_json(representative).decode("utf-8")
        group = groups.setdefault(signature_key, {
            "signature": signature,
            "count": 0,
            "representatives": {},
        })
        group["count"] += 1
        group["representatives"][representative_key] = representative
    summary_groups = []
    for signature_key in sorted(groups):
        group = groups[signature_key]
        representative_keys = sorted(group["representatives"])
        summary_groups.append({
            **group["signature"],
            "count": group["count"],
            "representative_variants": len(representative_keys),
            "representatives": [
                group["representatives"][key]
                for key in representative_keys[:_EDGE_DIAGNOSTIC_REPRESENTATIVE_LIMIT]
            ],
        })
    return {
        "raw_node_count": raw_node_count,
        "usable_upstream_node_id_count": len(upstream_to_hwm),
        "stringified_raw_node_id_count": len(raw_node_ids),
        "raw_edge_count": len(edges),
        "unresolved_edge_count": unresolved_total,
        "unresolved_source_only": source_only,
        "unresolved_target_only": target_only,
        "unresolved_both": both,
        "groups": summary_groups,
    }


def _raise_dangling_edge_inventory(edges: list, *, raw_node_count: int,
                                   raw_node_ids: set[str],
                                   upstream_to_hwm: dict[str, str]) -> None:
    summary = _dangling_edge_inventory(
        edges,
        raw_node_count=raw_node_count,
        raw_node_ids=raw_node_ids,
        upstream_to_hwm=upstream_to_hwm,
    )
    detail = "dangling edge endpoint inventory: " + canonical_json(summary).decode("utf-8")
    if len(detail) > _EDGE_DIAGNOSTIC_DETAIL_LIMIT:
        raise GraphOutputError("dangling edge endpoint inventory exceeds bounded detail capacity")
    raise GraphOutputError(detail)


def _json_value_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise GraphOutputError("Graphify node contains non-JSON value")


def _bounded_diagnostic_text(value: str, *, path: bool = False) -> str:
    value = unicodedata.normalize("NFC", value)
    value = "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in value)
    if path:
        value = value.replace("\\", "/").rsplit("/", 1)[-1]
    if len(value) <= _DIAGNOSTIC_VALUE_LIMIT:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    keep = _DIAGNOSTIC_VALUE_LIMIT - len(digest) - 2
    return value[:keep] + "~" + digest


def _diagnostic_field(node: dict, field: str) -> dict:
    if field not in node:
        return {"present": False, "type": "missing"}
    value = node[field]
    result = {"present": True, "type": _json_value_type(value)}
    if isinstance(value, str):
        result["value"] = _bounded_diagnostic_text(value, path=field == "source_file")
    elif value is None or isinstance(value, (bool, int, float)):
        result["value"] = value
    return result


def _source_location_shape(value: object) -> str:
    if not isinstance(value, str):
        return _json_value_type(value)
    value = value.strip()
    if re.fullmatch(r"L\d+", value):
        return "line"
    if re.fullmatch(r"L\d+-L?\d+", value):
        return "line-range"
    return "text"


def _missing_discriminator_signature(node: dict) -> dict:
    keys = sorted(node)
    source_file = node.get("source_file")
    label = node.get("label")
    return {
        "keys": keys,
        "key_types": {key: _json_value_type(node[key]) for key in keys},
        "label_matches_source_basename": bool(
            isinstance(source_file, str)
            and source_file
            and isinstance(label, str)
            and label
            and Path(source_file).name == label
        ),
        "source_location_shape": (
            _source_location_shape(node["source_location"])
            if "source_location" in node else "missing"
        ),
    }


def _is_d2_file_node(node: dict) -> bool:
    source_file = node.get("source_file")
    label = node.get("label")
    return (
        node.get("file_type") == "code"
        and isinstance(source_file, str) and source_file
        and isinstance(label, str) and label
        and Path(source_file).name == label
    )


_D3_CLASS_MISSING_DISCRIMINATOR_SIGNATURE = {
    "keys": [
        "_callable", "_callable_class", "_origin", "file_type",
        "id", "label", "source_file", "source_location",
    ],
    "key_types": {
        "_callable": "boolean",
        "_callable_class": "boolean",
        "_origin": "string",
        "file_type": "string",
        "id": "string",
        "label": "string",
        "source_file": "string",
        "source_location": "string",
    },
    "label_matches_source_basename": False,
    "source_location_shape": "line",
}

_D3_FUNCTION_MISSING_DISCRIMINATOR_SIGNATURE = {
    "keys": [
        "_callable", "_origin", "file_type", "id", "label",
        "source_file", "source_location",
    ],
    "key_types": {
        "_callable": "boolean",
        "_origin": "string",
        "file_type": "string",
        "id": "string",
        "label": "string",
        "source_file": "string",
        "source_location": "string",
    },
    "label_matches_source_basename": False,
    "source_location_shape": "line",
}


def _d3_compat_node_kind(node: dict) -> str | None:
    if node.get("file_type") != "code":
        return None
    signature = _missing_discriminator_signature(node)
    if signature == _D3_CLASS_MISSING_DISCRIMINATOR_SIGNATURE:
        kind = "class"
    elif signature == _D3_FUNCTION_MISSING_DISCRIMINATOR_SIGNATURE:
        kind = "function"
    else:
        return None
    if Path(node["source_file"]).name == node["label"]:
        return None
    return kind


def _missing_discriminator_kind(node: dict) -> str | None:
    kinds = []
    if _is_d2_file_node(node):
        kinds.append("file")
    d3_kind = _d3_compat_node_kind(node)
    if d3_kind is not None:
        kinds.append(d3_kind)
    if len(kinds) > 1:
        raise GraphOutputError("ambiguous missing-discriminator node kind")
    return kinds[0] if kinds else None


_D7A_SIX_KEYS = frozenset({"_origin", "file_type", "id", "label", "source_file", "source_location"})
_D7A_SOURCED_SIGNATURE = {
    "keys": sorted(_D7A_SIX_KEYS),
    "key_types": {key: "string" for key in sorted(_D7A_SIX_KEYS)},
    "label_matches_source_basename": False,
    "source_location_shape": "line",
}
_D7A_SOURCELESS_SIGNATURE = {
    "keys": sorted(_D7A_SIX_KEYS),
    "key_types": {key: "string" for key in sorted(_D7A_SIX_KEYS)},
    "label_matches_source_basename": False,
    "source_location_shape": "text",
}
_D7A_STRUCTURAL_PARENT_RELATIONS = frozenset({"contains", "defines", "method"})
_D7A_JSON_CODE_OUTGOING = frozenset({("contains", ""), ("extends", "import"), ("imports", "import")})
_D7A_JSON_CONCEPT_INCOMING = frozenset({("extends", "import"), ("imports", "import")})
_D7A_FAMILY_B_INCOMING = frozenset({
    ("calls", "call"),
    ("imports", "import"),
    ("references", "field"),
    ("references", "generic_arg"),
    ("references", "parameter_type"),
    ("references", "return_type"),
})
_D7A_FAMILY_ORDER = (
    "python_rationale",
    "json_code",
    "json_concept",
    "sourceless_reference_stub_family_b",
)
_D7A_PINNED_PRODUCT_SHA = "8fd669336b36064e842252d69fb4016cc526a9d4"
_D7A_PINNED_COUNTS = {
    "python_rationale": 46,
    "json_code": 31,
    "json_concept": 10,
    "sourceless_reference_stub_family_b": 255,
}


def _validate_graphify_nodes(nodes: list) -> None:
    for node in nodes:
        if not isinstance(node, dict):
            raise GraphOutputError("Graphify node is not an object")
        if not all(isinstance(key, str) for key in node):
            raise GraphOutputError("Graphify node key must be text")
        for key, value in node.items():
            if len(key) > 128:
                raise GraphOutputError("Graphify node key is too long")
            _json_value_type(value)
        upstream_id = node.get("id")
        if not isinstance(upstream_id, (str, int, float)) or isinstance(upstream_id, bool):
            raise GraphOutputError("Graphify node id is unusable")


def _d7a_edge_signature(edge: object) -> tuple[str, str] | None:
    if not isinstance(edge, dict):
        return None
    _, source = _selected_edge_endpoint(edge, "source", "from")
    _, target = _selected_edge_endpoint(edge, "target", "to")
    if source is None or target is None:
        return None
    relation = edge.get("relation", edge.get("type", edge.get("kind")))
    context = edge.get("context")
    if not isinstance(relation, str) or not relation:
        return None
    if context is None:
        context = ""
    if not isinstance(context, str):
        return None
    return relation, context


def _d7a_sourced_exact(node: dict, *, file_type: str, suffix: str, product_root: Path) -> bool:
    if (
        set(node) != _D7A_SIX_KEYS
        or _missing_discriminator_signature(node) != _D7A_SOURCED_SIGNATURE
        or node.get("_origin") != "ast"
        or node.get("file_type") != file_type
        or not node.get("id")
        or not node.get("label")
    ):
        return False
    source_file = node["source_file"]
    source_location = node["source_location"]
    if not source_file or not source_location:
        return False
    if Path(source_file.replace("\\", "/")).suffix.lower() != suffix:
        return False
    try:
        normalize_path(source_file, product_root)
        _lines(node)
    except GraphOutputError:
        return False
    return True


def _is_d7a_python_rationale(node: dict, *, incoming: list, outgoing: list,
                             product_root: Path, sourced_label_count: int) -> bool:
    del sourced_label_count
    return (
        _d7a_sourced_exact(node, file_type="rationale", suffix=".py", product_root=product_root)
        and not incoming
        and len(outgoing) == 1
        and _d7a_edge_signature(outgoing[0]) == ("rationale_for", "")
    )


def _is_d7a_json_code(node: dict, *, incoming: list, outgoing: list,
                      product_root: Path, sourced_label_count: int) -> bool:
    del sourced_label_count
    if not _d7a_sourced_exact(node, file_type="code", suffix=".json", product_root=product_root):
        return False
    if len(incoming) != 1 or _d7a_edge_signature(incoming[0]) != ("contains", ""):
        return False
    return all(_d7a_edge_signature(edge) in _D7A_JSON_CODE_OUTGOING for edge in outgoing)


def _is_d7a_json_concept(node: dict, *, incoming: list, outgoing: list,
                         product_root: Path, sourced_label_count: int) -> bool:
    del sourced_label_count
    return (
        _d7a_sourced_exact(node, file_type="concept", suffix=".json", product_root=product_root)
        and len(incoming) == 1
        and not outgoing
        and _d7a_edge_signature(incoming[0]) in _D7A_JSON_CONCEPT_INCOMING
    )


def _is_d7a_family_b(node: dict, *, incoming: list, outgoing: list,
                     product_root: Path, sourced_label_count: int) -> bool:
    del product_root
    if (
        set(node) != _D7A_SIX_KEYS
        or _missing_discriminator_signature(node) != _D7A_SOURCELESS_SIGNATURE
        or node.get("_origin") != "ast"
        or node.get("file_type") != "code"
        or not node.get("id")
        or not node.get("label")
        or node.get("source_file") != ""
        or node.get("source_location") != ""
        or not incoming
        or outgoing
        or sourced_label_count not in {0, 2}
    ):
        return False
    signatures = [_d7a_edge_signature(edge) for edge in incoming]
    if any(signature not in _D7A_FAMILY_B_INCOMING for signature in signatures):
        return False
    if any(signature is not None and signature[0] in _D7A_STRUCTURAL_PARENT_RELATIONS for signature in signatures):
        return False
    return True


def _select_d7a_omissions(nodes: list, edges: list, product_root: Path) -> tuple[set[str], dict[str, int]]:
    _validate_graphify_nodes(nodes)
    raw_node_ids = _raw_node_id_index(nodes)
    incoming_by_id = {node_id: [] for node_id in raw_node_ids}
    outgoing_by_id = {node_id: [] for node_id in raw_node_ids}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        _, source = _selected_edge_endpoint(edge, "source", "from")
        _, target = _selected_edge_endpoint(edge, "target", "to")
        if source is not None and str(source) in outgoing_by_id:
            outgoing_by_id[str(source)].append(edge)
        if target is not None and str(target) in incoming_by_id:
            incoming_by_id[str(target)].append(edge)
    sourced_labels: dict[str, int] = {}
    for node in nodes:
        label = node.get("label")
        source_file = node.get("source_file")
        if isinstance(label, str) and isinstance(source_file, str) and source_file:
            sourced_labels[label] = sourced_labels.get(label, 0) + 1
    rules = (
        ("python_rationale", _is_d7a_python_rationale),
        ("json_code", _is_d7a_json_code),
        ("json_concept", _is_d7a_json_concept),
        ("sourceless_reference_stub_family_b", _is_d7a_family_b),
    )
    omitted: set[str] = set()
    counts = {family: 0 for family in _D7A_FAMILY_ORDER}
    for node in sorted(nodes, key=lambda item: str(item["id"])):
        node_id_text = str(node["id"])
        label = node.get("label")
        candidate_count = sourced_labels.get(label, 0) if isinstance(label, str) else 0
        matches = [
            family
            for family, predicate in rules
            if predicate(
                node,
                incoming=incoming_by_id[node_id_text],
                outgoing=outgoing_by_id[node_id_text],
                product_root=product_root,
                sourced_label_count=candidate_count,
            )
        ]
        if len(matches) > 1:
            raise GraphOutputError("ambiguous D7-A omission compatibility rule")
        if matches:
            omitted.add(node_id_text)
            counts[matches[0]] += 1
    return omitted, counts


def _assert_d7a_pinned_counts(counts: dict[str, int]) -> None:
    if counts != _D7A_PINNED_COUNTS:
        raise GraphOutputError(
            "D7-A pinned omission count drift: expected="
            + canonical_json(_D7A_PINNED_COUNTS).decode("utf-8")
            + " observed=" + canonical_json(counts).decode("utf-8")
        )


def _d7a_incident_edge(edge: object, omitted_node_ids: set[str]) -> bool:
    if not isinstance(edge, dict):
        return False
    _, source = _selected_edge_endpoint(edge, "source", "from")
    _, target = _selected_edge_endpoint(edge, "target", "to")
    return (
        (source is not None and str(source) in omitted_node_ids)
        or (target is not None and str(target) in omitted_node_ids)
    )


_D7B_CPP_SUFFIXES = (".cpp", ".hpp")
_D7B_PINNED_PRODUCT_SHA = _D7A_PINNED_PRODUCT_SHA
_D7B_PINNED_COUNTS = {".cpp": 50, ".hpp": 333}
_D7B_STRUCTURAL_PARENT = ("defines", "field")


def _select_d7b_cpp_source_ast_kinds(nodes: list, edges: list, product_root: Path) -> tuple[dict[str, str], dict[str, int], dict[str, int]]:
    _validate_graphify_nodes(nodes)
    raw_node_ids = _raw_node_id_index(nodes)
    node_by_id = {str(node["id"]): node for node in nodes}
    incoming_by_id = {node_id: [] for node_id in raw_node_ids}
    outgoing_by_id = {node_id: [] for node_id in raw_node_ids}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        _, source = _selected_edge_endpoint(edge, "source", "from")
        _, target = _selected_edge_endpoint(edge, "target", "to")
        if source is not None and str(source) in outgoing_by_id:
            outgoing_by_id[str(source)].append(edge)
        if target is not None and str(target) in incoming_by_id:
            incoming_by_id[str(target)].append(edge)

    source_counts = {suffix: 0 for suffix in _D7B_CPP_SUFFIXES}
    classified_counts = {suffix: 0 for suffix in _D7B_CPP_SUFFIXES}
    classified: dict[str, str] = {}
    for node in sorted(nodes, key=lambda item: str(item["id"])):
        if any(key in node for key in ("type", "kind", "node_type")):
            continue
        source_file = node.get("source_file")
        suffix = (
            Path(source_file.replace("\\", "/")).suffix.lower()
            if isinstance(source_file, str) and source_file else ""
        )
        if suffix not in _D7B_CPP_SUFFIXES:
            continue
        if not _d7a_sourced_exact(node, file_type="code", suffix=suffix, product_root=product_root):
            continue
        source_counts[suffix] += 1
        node_id_text = str(node["id"])
        if outgoing_by_id[node_id_text]:
            continue
        structural_incoming = []
        for edge in incoming_by_id[node_id_text]:
            relation = edge.get("relation", edge.get("type", edge.get("kind")))
            if isinstance(relation, str) and relation in _D7A_STRUCTURAL_PARENT_RELATIONS:
                structural_incoming.append(edge)
        if len(structural_incoming) != 1:
            continue
        parent_edge = structural_incoming[0]
        if _d7a_edge_signature(parent_edge) != _D7B_STRUCTURAL_PARENT:
            continue
        _, parent_id = _selected_edge_endpoint(parent_edge, "source", "from")
        parent = node_by_id.get(str(parent_id))
        if parent is None:
            continue
        if any(key in parent for key in ("type", "kind", "node_type")):
            parent_kind = _node_kind(parent)
        else:
            parent_kind = _missing_discriminator_kind(parent)
        if parent_kind != "class":
            continue
        classified[node_id_text] = "field"
        classified_counts[suffix] += 1
    return classified, source_counts, classified_counts


def _assert_d7b_pinned_counts(source_counts: dict[str, int], classified_counts: dict[str, int]) -> None:
    if source_counts != _D7B_PINNED_COUNTS or classified_counts != _D7B_PINNED_COUNTS:
        raise GraphOutputError(
            "D7-B pinned classification count drift: expected="
            + canonical_json(_D7B_PINNED_COUNTS).decode("utf-8")
            + " source=" + canonical_json(source_counts).decode("utf-8")
            + " classified=" + canonical_json(classified_counts).decode("utf-8")
        )


def _preflight_missing_node_discriminators(nodes: list, d7b_kinds: dict[str, str] | None = None) -> None:
    _validate_graphify_nodes(nodes)
    groups: dict[str, dict] = {}
    d7b_kinds = d7b_kinds or {}
    for node in nodes:
        if any(key in node for key in ("type", "kind", "node_type")):
            continue
        fallback = _missing_discriminator_kind(node)
        d7b_kind = d7b_kinds.get(str(node["id"]))
        if fallback is not None and d7b_kind is not None and fallback != d7b_kind:
            raise GraphOutputError("ambiguous missing-discriminator node kind")
        if fallback is not None or d7b_kind is not None:
            continue
        signature = _missing_discriminator_signature(node)
        signature_key = canonical_json(signature).decode("utf-8")
        representative = {field: _diagnostic_field(node, field) for field in _DIAGNOSTIC_FIELDS}
        representative_key = canonical_json(representative).decode("utf-8")
        group = groups.setdefault(signature_key, {
            "signature": signature,
            "count": 0,
            "representatives": {},
        })
        group["count"] += 1
        group["representatives"][representative_key] = representative
    if not groups:
        return
    summary_groups = []
    for signature_key in sorted(groups):
        group = groups[signature_key]
        representative_keys = sorted(group["representatives"])
        summary_groups.append({
            **group["signature"],
            "count": group["count"],
            "representative_variants": len(representative_keys),
            "representatives": [
                group["representatives"][key]
                for key in representative_keys[:_DIAGNOSTIC_REPRESENTATIVE_LIMIT]
            ],
        })
    summary = {
        "groups": summary_groups,
        "total": sum(group["count"] for group in groups.values()),
    }
    detail = "missing node discriminator inventory: " + canonical_json(summary).decode("utf-8")
    if len(detail) > _DIAGNOSTIC_DETAIL_LIMIT:
        raise GraphOutputError("missing node discriminator inventory exceeds bounded detail capacity")
    raise GraphOutputError(detail)


def _node_kind(node: dict, d7b_kind: str | None = None) -> str:
    if not any(key in node for key in ("type", "kind", "node_type")):
        fallback = _missing_discriminator_kind(node)
        if fallback is not None and d7b_kind is not None and fallback != d7b_kind:
            raise GraphOutputError("ambiguous missing-discriminator node kind")
        if d7b_kind is not None:
            return d7b_kind
        if fallback is not None:
            return fallback
    value = node.get("type", node.get("kind", node.get("node_type")))
    return _text(value, field="node kind", max_len=64, nonempty=True)


def _qualified_name(node: dict) -> str:
    value = node.get("label", node.get("name"))
    return _text(value, field="qualified name", max_len=4096)


def node_id(kind: str, path: str, qualified_name: str, start: int, end: int) -> str:
    raw = f"node\0{kind}\0{path}\0{qualified_name}\0{start}\0{end}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def edge_id(source: str, target: str, kind: str) -> str:
    return hashlib.sha256(f"edge\0{source}\0{target}\0{kind}".encode("utf-8")).hexdigest()


def normalize_graph(graph: object, product_sha: str, product_root: Path) -> tuple[dict, bytes, str]:
    if not re.fullmatch(r"[0-9a-f]{40}", product_sha):
        raise GraphOutputError("requested product SHA must be exact 40-hex")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise GraphOutputError("Graphify graph.json must contain node and edge arrays")
    _validate_graphify_nodes(graph["nodes"])
    raw_node_ids = _raw_node_id_index(graph["nodes"])
    omitted_node_ids, d7a_counts = _select_d7a_omissions(graph["nodes"], graph["edges"], product_root)
    if product_sha == _D7A_PINNED_PRODUCT_SHA:
        _assert_d7a_pinned_counts(d7a_counts)
    if omitted_node_ids:
        print("hwm_d7a_omitted_nodes=" + canonical_json(d7a_counts).decode("utf-8"), flush=True)
    remaining_nodes = [node for node in graph["nodes"] if str(node["id"]) not in omitted_node_ids]
    remaining_edges = [edge for edge in graph["edges"] if not _d7a_incident_edge(edge, omitted_node_ids)]
    d7b_kinds, d7b_source_counts, d7b_classified_counts = _select_d7b_cpp_source_ast_kinds(
        remaining_nodes, remaining_edges, product_root
    )
    if product_sha == _D7B_PINNED_PRODUCT_SHA and any(d7b_source_counts.values()):
        _assert_d7b_pinned_counts(d7b_source_counts, d7b_classified_counts)
    _preflight_missing_node_discriminators(remaining_nodes, d7b_kinds)
    upstream_to_hwm: dict[str, str] = {}
    nodes_by_id: dict[str, dict] = {}
    for upstream in remaining_nodes:
        if not isinstance(upstream, dict):
            raise GraphOutputError("Graphify node is not an object")
        upstream_id = upstream.get("id")
        if not isinstance(upstream_id, (str, int, float)) or isinstance(upstream_id, bool):
            raise GraphOutputError("Graphify node id is unusable")
        upstream_id = str(upstream_id)
        kind = _node_kind(upstream, d7b_kinds.get(upstream_id))
        path = normalize_path(upstream.get("source_file", upstream.get("path")), product_root)
        qname = _qualified_name(upstream)
        start, end = _lines(upstream)
        ident = node_id(kind, path, qname, start, end)
        normalized = {"id": ident, "kind": kind, "path": path, "qualified_name": qname,
                      "start_line": start, "end_line": end}
        previous = upstream_to_hwm.get(upstream_id)
        if previous is not None and previous != ident:
            raise GraphOutputError("one upstream id maps to conflicting structural nodes")
        upstream_to_hwm[upstream_id] = ident
        existing = nodes_by_id.get(ident)
        if existing is not None and existing != normalized:
            raise GraphOutputError("canonical node id collision")
        nodes_by_id[ident] = normalized
    edges_by_id: dict[str, dict] = {}
    omitted_unrepresented_target_edges = 0
    for upstream in remaining_edges:
        if not isinstance(upstream, dict):
            raise GraphOutputError("Graphify edge is not an object")
        src = upstream.get("source", upstream.get("from"))
        dst = upstream.get("target", upstream.get("to"))
        if src is None or dst is None:
            raise GraphOutputError("Graphify edge endpoint missing")
        kind = _text(upstream.get("relation", upstream.get("type", upstream.get("kind"))),
                     field="edge kind", max_len=64, nonempty=True)
        src_text, dst_text = str(src), str(dst)
        src_id, dst_id = upstream_to_hwm.get(src_text), upstream_to_hwm.get(dst_text)
        if src_id is None or dst_id is None:
            if (
                src_id is not None
                and src_text in raw_node_ids
                and isinstance(dst, str)
                and dst_text not in raw_node_ids
            ):
                omitted_unrepresented_target_edges += 1
                continue
            _raise_dangling_edge_inventory(
                remaining_edges,
                raw_node_count=len(graph["nodes"]),
                raw_node_ids=raw_node_ids,
                upstream_to_hwm=upstream_to_hwm,
            )
        ident = edge_id(src_id, dst_id, kind)
        normalized = {"id": ident, "source": src_id, "target": dst_id, "kind": kind}
        existing = edges_by_id.get(ident)
        if existing is not None and existing != normalized:
            raise GraphOutputError("canonical edge id collision")
        edges_by_id[ident] = normalized
    print(f"hwm_omitted_unrepresented_target_edges={omitted_unrepresented_target_edges}", flush=True)
    nodes = sorted(nodes_by_id.values(), key=lambda n: (
        n["path"], n["kind"], n["qualified_name"], n["start_line"], n["end_line"], n["id"]))
    edges = sorted(edges_by_id.values(), key=lambda e: (e["source"], e["target"], e["kind"], e["id"]))
    payload = {
        "schema": "hwm-graph-snapshot/v1",
        "product_repository": PRODUCT_REPOSITORY,
        "product_sha": product_sha,
        "supply_chain": {
            "repository": UPSTREAM_REPOSITORY, "tag": UPSTREAM_TAG, "commit": UPSTREAM_COMMIT,
            "package": GRAPHIFY_PACKAGE, "package_version": GRAPHIFY_VERSION,
            "artifact_sha256": GRAPHIFY_WHEEL_SHA256, "python_version": RUNTIME_VERSION,
            "mode": "structural-code-only",
        },
        "canonicalization": CANONICALIZATION,
        "nodes": nodes,
        "edges": edges,
    }
    payload_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
    snapshot = dict(payload, canonical_payload_sha256=payload_hash)
    validate_snapshot(snapshot)
    encoded = canonical_json(snapshot)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise OversizedSnapshotError(f"canonical snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
    return snapshot, encoded, hashlib.sha256(encoded).hexdigest()


def validate_snapshot(snapshot: object) -> None:
    if not isinstance(snapshot, dict):
        raise SnapshotSchemaError("snapshot must be object")
    required = {"schema", "product_repository", "product_sha", "supply_chain", "canonicalization",
                "nodes", "edges", "canonical_payload_sha256"}
    if set(snapshot) != required:
        raise SnapshotSchemaError("snapshot keys differ from graph-snapshot v1")
    if snapshot["schema"] != "hwm-graph-snapshot/v1" or snapshot["product_repository"] != PRODUCT_REPOSITORY:
        raise SnapshotSchemaError("snapshot schema/repository mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", snapshot["product_sha"]):
        raise SnapshotSchemaError("snapshot product_sha invalid")
    expected_supply = {
        "repository": UPSTREAM_REPOSITORY, "tag": UPSTREAM_TAG, "commit": UPSTREAM_COMMIT,
        "package": GRAPHIFY_PACKAGE, "package_version": GRAPHIFY_VERSION,
        "artifact_sha256": GRAPHIFY_WHEEL_SHA256, "python_version": RUNTIME_VERSION,
        "mode": "structural-code-only",
    }
    if snapshot["supply_chain"] != expected_supply or snapshot["canonicalization"] != CANONICALIZATION:
        raise SnapshotSchemaError("snapshot supply chain/canonicalization mismatch")
    if not isinstance(snapshot["nodes"], list) or len(snapshot["nodes"]) > 1_000_000:
        raise SnapshotSchemaError("node array invalid")
    if not isinstance(snapshot["edges"], list) or len(snapshot["edges"]) > 3_000_000:
        raise SnapshotSchemaError("edge array invalid")
    node_ids = set()
    for node in snapshot["nodes"]:
        if not isinstance(node, dict) or set(node) != {"id", "kind", "path", "qualified_name", "start_line", "end_line"}:
            raise SnapshotSchemaError("node schema invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", node["id"]): raise SnapshotSchemaError("node id invalid")
        if not isinstance(node["kind"], str) or not 1 <= len(node["kind"]) <= 64: raise SnapshotSchemaError("node kind invalid")
        if not isinstance(node["path"], str) or len(node["path"]) > 4096 or node["path"].startswith("/") or "\\" in node["path"]:
            raise SnapshotSchemaError("node path invalid")
        parts = PurePosixPath(node["path"]).parts
        if not parts or any(p in {".", ".."} for p in parts): raise SnapshotSchemaError("node path segment invalid")
        if not isinstance(node["qualified_name"], str) or len(node["qualified_name"]) > 4096: raise SnapshotSchemaError("qname invalid")
        if not isinstance(node["start_line"], int) or node["start_line"] < 1 or not isinstance(node["end_line"], int) or node["end_line"] < 1:
            raise SnapshotSchemaError("node line invalid")
        node_ids.add(node["id"])
    for edge in snapshot["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"id", "source", "target", "kind"}: raise SnapshotSchemaError("edge schema invalid")
        if not all(isinstance(edge[k], str) and re.fullmatch(r"[0-9a-f]{64}", edge[k]) for k in ("id", "source", "target")):
            raise SnapshotSchemaError("edge id invalid")
        if edge["source"] not in node_ids or edge["target"] not in node_ids: raise SnapshotSchemaError("edge endpoint invalid")
        if not isinstance(edge["kind"], str) or not 1 <= len(edge["kind"]) <= 64: raise SnapshotSchemaError("edge kind invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot["canonical_payload_sha256"]):
        raise SnapshotSchemaError("canonical payload digest invalid")
    payload = dict(snapshot); digest = payload.pop("canonical_payload_sha256")
    if hashlib.sha256(canonical_json(payload)).hexdigest() != digest:
        raise SnapshotSchemaError("canonical payload digest mismatch")
