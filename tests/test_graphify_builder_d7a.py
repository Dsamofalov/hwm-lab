from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from graphify_builder import normalize

PINNED_SHA = "8fd669336b36064e842252d69fb4016cc526a9d4"
SYNTHETIC_SHA = "1111111111111111111111111111111111111111"


def explicit(node_id: str, kind: str = "class", label: str | None = None, path: str | None = None, line: int = 1) -> dict:
    return {
        "id": node_id,
        "type": kind,
        "label": label or node_id,
        "source_file": path or f"src/{node_id}.py",
        "source_location": f"L{line}",
    }


def rationale(node_id: str = "rationale") -> dict:
    return {
        "_origin": "ast",
        "file_type": "rationale",
        "id": node_id,
        "label": f"why-{node_id}",
        "source_file": f"src/{node_id}.py",
        "source_location": "L7",
    }


def json_code(node_id: str = "json-code", path: str = "config/settings.json") -> dict:
    return {
        "_origin": "ast",
        "file_type": "code",
        "id": node_id,
        "label": f"setting-{node_id}",
        "source_file": path,
        "source_location": "L3",
    }


def json_concept(node_id: str = "json-concept", path: str = "config/settings.json") -> dict:
    return {
        "_origin": "ast",
        "file_type": "concept",
        "id": node_id,
        "label": f"concept-{node_id}",
        "source_file": path,
        "source_location": "L4",
    }


def stub(node_id: str = "stub", label: str | None = None) -> dict:
    return {
        "_origin": "ast",
        "file_type": "code",
        "id": node_id,
        "label": label or f"External{node_id}",
        "source_file": "",
        "source_location": "",
    }


def graph_with_all_families() -> dict:
    nodes = [
        explicit("keep-a", "class", "KeepA", "src/a.py", 1),
        explicit("keep-b", "function", "keep_b", "src/b.py", 2),
        explicit("json-file", "file", "settings.json", "config/settings.json", 1),
        rationale(),
        json_code(),
        json_code("json-child"),
        json_concept(),
        stub(),
    ]
    edges = [
        {"source": "keep-a", "target": "keep-b", "relation": "calls"},
        {"source": "rationale", "target": "keep-a", "relation": "rationale_for"},
        {"source": "json-file", "target": "json-code", "relation": "contains"},
        {"source": "json-code", "target": "json-child", "relation": "contains"},
        {"source": "json-code", "target": "json-concept", "relation": "extends", "context": "import"},
        {"source": "keep-b", "target": "stub", "relation": "references", "context": "parameter_type"},
    ]
    return {"nodes": nodes, "edges": edges}


def pinned_count_graph(*, json_code_count: int = 31) -> dict:
    nodes = [
        explicit("keep", "class", "Keep", "src/keep.py"),
        explicit("json-file", "file", "all.json", "config/all.json"),
    ]
    edges: list[dict] = []
    for i in range(46):
        node_id = f"r{i}"
        nodes.append(rationale(node_id))
        edges.append({"source": node_id, "target": "keep", "relation": "rationale_for"})
    for i in range(json_code_count):
        node_id = f"jc{i}"
        nodes.append(json_code(node_id, "config/all.json"))
        edges.append({"source": "json-file", "target": node_id, "relation": "contains"})
    for i in range(10):
        node_id = f"concept{i}"
        nodes.append(json_concept(node_id, "config/all.json"))
        relation = "extends" if i < 9 else "imports"
        edges.append({"source": "keep", "target": node_id, "relation": relation, "context": "import"})
    for i in range(4):
        label = f"Ambiguous{i}"
        nodes.extend([
            explicit(f"amb-{i}-a", "class", label, f"src/amb-{i}-a.hpp", 20 + i),
            explicit(f"amb-{i}-b", "class", label, f"src/amb-{i}-b.hpp", 30 + i),
        ])
    for i in range(255):
        node_id = f"stub{i}"
        label = f"Ambiguous{i}" if i < 4 else f"ZeroCandidate{i}"
        nodes.append(stub(node_id, label))
        edges.append({"source": "keep", "target": node_id, "relation": "references", "context": "parameter_type"})
    return {"nodes": nodes, "edges": edges}


class D7AExactOmissionTests(unittest.TestCase):
    def normalize(self, graph: dict, product_sha: str = SYNTHETIC_SHA):
        with tempfile.TemporaryDirectory() as d:
            return normalize.normalize_graph(graph, product_sha, Path(d))

    def assert_rejected(self, node: dict, edges: list[dict], extra_nodes: list[dict] | None = None, message: str | None = None):
        g = {
            "nodes": [explicit("keep", "class", "Keep", "src/keep.py"), *(extra_nodes or []), node],
            "edges": edges,
        }
        cm = self.assertRaisesRegex(normalize.GraphOutputError, message) if message else self.assertRaises(normalize.GraphOutputError)
        with cm:
            self.normalize(g)

    def test_positive_exact_python_rationale_omits_node_and_all_incident_edges(self):
        g = {
            "nodes": [explicit("keep"), rationale()],
            "edges": [
                {"source": "rationale", "target": "keep", "relation": "rationale_for"},
            ],
        }
        snapshot, _, _ = self.normalize(g)
        self.assertEqual([node["qualified_name"] for node in snapshot["nodes"]], ["keep"])
        self.assertEqual(snapshot["edges"], [])

    def test_positive_exact_json_code_including_nested_contains_is_omitted(self):
        g = {
            "nodes": [
                explicit("file", "file", "settings.json", "config/settings.json"),
                json_code("outer"),
                json_code("inner"),
                json_concept("concept"),
            ],
            "edges": [
                {"source": "file", "target": "outer", "relation": "contains"},
                {"source": "outer", "target": "inner", "relation": "contains"},
                {"source": "outer", "target": "concept", "relation": "extends", "context": "import"},
            ],
        }
        snapshot, _, _ = self.normalize(g)
        self.assertEqual([(node["kind"], node["qualified_name"]) for node in snapshot["nodes"]], [("file", "settings.json")])
        self.assertEqual(snapshot["edges"], [])

    def test_positive_exact_json_concept_relation_partition_is_omitted(self):
        for relation in ("extends", "imports"):
            with self.subTest(relation=relation):
                g = {
                    "nodes": [explicit("keep"), json_concept()],
                    "edges": [{"source": "keep", "target": "json-concept", "relation": relation, "context": "import"}],
                }
                snapshot, _, _ = self.normalize(g)
                self.assertEqual([node["qualified_name"] for node in snapshot["nodes"]], ["keep"])
                self.assertEqual(snapshot["edges"], [])

    def test_positive_exact_family_b_zero_and_ambiguous_same_label_stubs_are_omitted(self):
        for candidates in (0, 2):
            with self.subTest(candidates=candidates):
                same = [explicit(f"candidate-{i}", "class", "Externalstub", f"src/candidate-{i}.hpp", i + 3) for i in range(candidates)]
                g = {
                    "nodes": [explicit("keep"), *same, stub()],
                    "edges": [{"source": "keep", "target": "stub", "relation": "references", "context": "return_type"}],
                }
                snapshot, _, _ = self.normalize(g)
                self.assertNotIn("Externalstub", [node["qualified_name"] for node in snapshot["nodes"] if node["path"] == ""])
                self.assertEqual(len(snapshot["edges"]), 0)

    def test_family_b_accepts_only_proven_incoming_contexts(self):
        contexts = (
            ("calls", "call"),
            ("imports", "import"),
            ("references", "field"),
            ("references", "generic_arg"),
            ("references", "parameter_type"),
            ("references", "return_type"),
        )
        for relation, context in contexts:
            with self.subTest(relation=relation, context=context):
                g = {"nodes": [explicit("keep"), stub()], "edges": [{"source": "keep", "target": "stub", "relation": relation, "context": context}]}
                snapshot, _, _ = self.normalize(g)
                self.assertEqual(len(snapshot["nodes"]), 1)
                self.assertEqual(snapshot["edges"], [])

    def test_one_material_condition_at_a_time_negative_matrix(self):
        cases: list[tuple[str, dict, list[dict], list[dict]]] = []
        r = rationale()
        cases.extend([
            ("rationale-extra-key", {**r, "extra": "x"}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-origin", {**r, "_origin": "source"}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-file-type", {**r, "file_type": "code"}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-suffix", {**r, "source_file": "src/rationale.txt"}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-empty-source", {**r, "source_file": ""}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-invalid-location", {**r, "source_location": "L0"}, [{"source": "rationale", "target": "keep", "relation": "rationale_for"}], []),
            ("rationale-no-outgoing", r, [], []),
            ("rationale-wrong-outgoing", r, [{"source": "rationale", "target": "keep", "relation": "calls"}], []),
        ])
        j = json_code()
        cases.extend([
            ("json-code-extra-key", {**j, "extra": "x"}, [{"source": "keep", "target": "json-code", "relation": "contains"}], []),
            ("json-code-origin", {**j, "_origin": "source"}, [{"source": "keep", "target": "json-code", "relation": "contains"}], []),
            ("json-code-suffix", {**j, "source_file": "config/settings.yaml"}, [{"source": "keep", "target": "json-code", "relation": "contains"}], []),
            ("json-code-no-parent", j, [], []),
            ("json-code-wrong-parent", j, [{"source": "keep", "target": "json-code", "relation": "calls"}], []),
            ("json-code-invalid-outgoing", j, [{"source": "keep", "target": "json-code", "relation": "contains"}, {"source": "json-code", "target": "keep", "relation": "calls"}], []),
        ])
        c = json_concept()
        cases.extend([
            ("json-concept-file-type", {**c, "file_type": "unknown"}, [{"source": "keep", "target": "json-concept", "relation": "extends", "context": "import"}], []),
            ("json-concept-wrong-context", c, [{"source": "keep", "target": "json-concept", "relation": "extends", "context": "field"}], []),
            ("json-concept-outgoing", c, [{"source": "keep", "target": "json-concept", "relation": "extends", "context": "import"}, {"source": "json-concept", "target": "keep", "relation": "imports", "context": "import"}], []),
        ])
        s = stub()
        cases.extend([
            ("stub-nonempty-source", {**s, "source_file": "src/external.hpp"}, [{"source": "keep", "target": "stub", "relation": "references", "context": "field"}], []),
            ("stub-nonempty-location", {**s, "source_location": "L1"}, [{"source": "keep", "target": "stub", "relation": "references", "context": "field"}], []),
            ("stub-no-incoming", s, [], []),
            ("stub-unsupported-context", s, [{"source": "keep", "target": "stub", "relation": "calls"}], []),
            ("stub-outgoing", s, [{"source": "keep", "target": "stub", "relation": "references", "context": "field"}, {"source": "stub", "target": "keep", "relation": "calls", "context": "call"}], []),
            ("stub-structural-parent", s, [{"source": "keep", "target": "stub", "relation": "contains"}], []),
            ("stub-one-candidate", s, [{"source": "keep", "target": "stub", "relation": "references", "context": "field"}], [explicit("one-candidate", "class", "Externalstub", "src/candidate.hpp", 9)]),
        ])
        for name, node, edges, extra_nodes in cases:
            with self.subTest(name=name):
                self.assert_rejected(node, edges, extra_nodes)

    def test_overlap_between_compatibility_rules_fails_closed(self):
        node = rationale()
        edges = [{"source": "rationale", "target": "keep", "relation": "rationale_for"}]
        with mock.patch.object(normalize, "_is_d7a_python_rationale", return_value=True), mock.patch.object(normalize, "_is_d7a_json_code", return_value=True):
            with self.assertRaisesRegex(normalize.GraphOutputError, "ambiguous D7-A omission compatibility rule"):
                normalize._select_d7a_omissions([explicit("keep"), node], edges, Path("."))

    def test_exact_pinned_family_counts_and_count_drift_fail_closed(self):
        graph = pinned_count_graph()
        expected = {
            "python_rationale": 46,
            "json_code": 31,
            "json_concept": 10,
            "sourceless_reference_stub_family_b": 255,
        }
        omitted, counts = normalize._select_d7a_omissions(graph["nodes"], graph["edges"], Path("."))
        self.assertEqual(counts, expected)
        self.assertEqual(len(omitted), 342)
        normalize._assert_d7a_pinned_counts(counts)
        drift = dict(counts); drift["json_code"] -= 1
        with self.assertRaisesRegex(normalize.GraphOutputError, "D7-A pinned omission count drift"):
            normalize._assert_d7a_pinned_counts(drift)

    def test_production_path_pinned_sha_accepts_exact_d7a_counts(self):
        snapshot, _, _ = self.normalize(pinned_count_graph(), PINNED_SHA)
        self.assertEqual(snapshot["product_sha"], PINNED_SHA)

    def test_production_path_pinned_sha_rejects_count_drift(self):
        with self.assertRaisesRegex(normalize.GraphOutputError, "D7-A pinned omission count drift"):
            self.normalize(pinned_count_graph(json_code_count=30), PINNED_SHA)

    def test_production_path_non_pinned_sha_does_not_require_pinned_counts(self):
        snapshot, _, _ = self.normalize(graph_with_all_families(), SYNTHETIC_SHA)
        self.assertEqual(snapshot["product_sha"], SYNTHETIC_SHA)

    def test_all_incident_edges_removed_nonincident_graph_is_byte_exact(self):
        baseline = {
            "nodes": [
                explicit("keep-a", "class", "KeepA", "src/a.py", 1),
                explicit("keep-b", "function", "keep_b", "src/b.py", 2),
                explicit("json-file", "file", "settings.json", "config/settings.json", 1),
            ],
            "edges": [{"source": "keep-a", "target": "keep-b", "relation": "calls"}],
        }
        with_omissions = graph_with_all_families()
        expected = self.normalize(baseline)
        actual = self.normalize(with_omissions)
        self.assertEqual(actual, expected)
        self.assertEqual(hashlib.sha256(actual[1]).hexdigest(), actual[2])

    def test_raw_input_reordering_does_not_change_canonical_bytes_or_digest(self):
        g = graph_with_all_families()
        reversed_graph = {"nodes": list(reversed(g["nodes"])), "edges": list(reversed(g["edges"]))}
        first = self.normalize(g)
        second = self.normalize(reversed_graph)
        self.assertEqual(first, second)

    def test_explicit_discriminator_precedence_d2_d4_and_d5_are_preserved(self):
        explicit_rationale = {**rationale(), "type": "class"}
        g = {
            "nodes": [explicit("keep"), explicit_rationale],
            "edges": [{"source": "rationale", "target": "keep", "relation": "rationale_for"}],
        }
        snapshot, _, _ = self.normalize(g)
        self.assertEqual({node["qualified_name"]: node["kind"] for node in snapshot["nodes"]}, {"keep": "class", "why-rationale": "class"})
        d2 = {"id": "file", "label": "a.py", "file_type": "code", "source_file": "a.py", "source_location": "L1"}
        d4_class = {"_callable": True, "_callable_class": False, "_origin": "source", "file_type": "code", "id": "class", "label": "A", "source_file": "a.py", "source_location": "L2"}
        d4_function = {"_callable": False, "_origin": "source", "file_type": "code", "id": "fn", "label": "f()", "source_file": "a.py", "source_location": "L3"}
        self.assertEqual((normalize._node_kind(d2), normalize._node_kind(d4_class), normalize._node_kind(d4_function)), ("file", "class", "function"))
        with self.assertRaisesRegex(normalize.GraphOutputError, "dangling edge endpoint inventory"):
            self.normalize({"nodes": [explicit("keep")], "edges": [{"source": "missing", "target": "keep", "relation": "calls"}]})

    def test_unknown_shape_raw_id_collision_and_no_new_canonical_kind_fail_closed(self):
        bad = {**json_code(), "symbol_scope": ["local"]}
        self.assert_rejected(bad, [{"source": "keep", "target": "json-code", "relation": "contains"}])
        colliding = [
            {"id": 1, "type": "class", "label": "A", "source_file": "a.py", "source_location": "L1"},
            {"id": "1", "type": "class", "label": "B", "source_file": "b.py", "source_location": "L2"},
            stub("stub-collision"),
        ]
        with self.assertRaisesRegex(normalize.GraphOutputError, "raw node id stringification collision inventory"):
            self.normalize({"nodes": colliding, "edges": [{"source": "1", "target": "stub-collision", "relation": "references", "context": "field"}]})
        snapshot, _, _ = self.normalize(graph_with_all_families())
        self.assertEqual({node["kind"] for node in snapshot["nodes"]}, {"class", "function", "file"})


if __name__ == "__main__":
    unittest.main()
