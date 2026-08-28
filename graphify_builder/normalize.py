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


def _preflight_missing_node_discriminators(nodes: list) -> None:
    groups: dict[str, dict] = {}
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
        if any(key in node for key in ("type", "kind", "node_type")):
            continue
        if _is_d2_file_node(node):
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


def _node_kind(node: dict) -> str:
    if not any(key in node for key in ("type", "kind", "node_type")):
        source_file = node.get("source_file")
        label = node.get("label")
        if (
            node.get("file_type") == "code"
            and isinstance(source_file, str) and source_file
            and isinstance(label, str) and label
            and Path(source_file).name == label
        ):
            return "file"
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
    _preflight_missing_node_discriminators(graph["nodes"])
    upstream_to_hwm: dict[str, str] = {}
    nodes_by_id: dict[str, dict] = {}
    for upstream in graph["nodes"]:
        if not isinstance(upstream, dict):
            raise GraphOutputError("Graphify node is not an object")
        upstream_id = upstream.get("id")
        if not isinstance(upstream_id, (str, int, float)) or isinstance(upstream_id, bool):
            raise GraphOutputError("Graphify node id is unusable")
        upstream_id = str(upstream_id)
        kind = _node_kind(upstream)
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
    for upstream in graph["edges"]:
        if not isinstance(upstream, dict):
            raise GraphOutputError("Graphify edge is not an object")
        src = upstream.get("source", upstream.get("from"))
        dst = upstream.get("target", upstream.get("to"))
        if src is None or dst is None:
            raise GraphOutputError("Graphify edge endpoint missing")
        src_id, dst_id = upstream_to_hwm.get(str(src)), upstream_to_hwm.get(str(dst))
        if src_id is None or dst_id is None:
            raise GraphOutputError("Graphify edge references missing structural node")
        kind = _text(upstream.get("relation", upstream.get("type", upstream.get("kind"))),
                     field="edge kind", max_len=64, nonempty=True)
        ident = edge_id(src_id, dst_id, kind)
        normalized = {"id": ident, "source": src_id, "target": dst_id, "kind": kind}
        existing = edges_by_id.get(ident)
        if existing is not None and existing != normalized:
            raise GraphOutputError("canonical edge id collision")
        edges_by_id[ident] = normalized
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
