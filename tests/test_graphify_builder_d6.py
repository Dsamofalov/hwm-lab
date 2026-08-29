from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from graphify_builder import normalize

SHA = "8fd669336b36064e842252d69fb4016cc526a9d4"


def explicit_node(node_id: object, kind: str, label: str, path: str, line: str = "L1") -> dict:
    return {
        "id": node_id,
        "type": kind,
        "label": label,
        "source_file": path,
        "source_location": line,
    }


def d6_nodes() -> list[dict]:
    return [
        explicit_node("setup", "module", "setup", "setup.py"),
        explicit_node("sitecustomize", "module", "sitecustomize", "sitecustomize.py"),
        explicit_node("pkg", "module", "pkg", "pkg/__init__.py"),
        explicit_node("A", "class", "A", "pkg/a.py"),
        explicit_node("f", "function", "f", "pkg/a.py", "L3"),
    ]


def d6_edges() -> list[dict]:
    return [
        {"source": "setup", "target": "pathlib", "relation": "imports"},
        {"source": "sitecustomize", "target": "pathlib", "relation": "imports"},
        {"source": "pkg", "target": "A", "relation": "contains"},
        {"source": "A", "target": "f", "relation": "contains"},
        {"source": "f", "target": "A", "relation": "calls"},
    ]


def d4_file_node() -> dict:
    return {"id": "pkg_a", "label": "a.py", "file_type": "code", "source_file": "a.py", "source_location": "L1"}


def d4_class_node() -> dict:
    return {"_callable": True, "_callable_class": False, "_origin": "source", "file_type": "code", "id": "pkg_a_a", "label": "A", "source_file": "a.py", "source_location": "L1"}


def d4_function_node() -> dict:
    return {"_callable": False, "_origin": "source", "file_type": "code", "id": "pkg_a_f", "label": "f()", "source_file": "a.py", "source_location": "L3"}


class D6CanonicalUnrepresentedTargetTests(unittest.TestCase):
    def normalize(self, graph: dict):
        with tempfile.TemporaryDirectory() as d:
            return normalize.normalize_graph(graph, SHA, Path(d))

    def test_resolved_source_string_target_absent_from_complete_raw_nodes_is_omitted(self):
        nodes = [
            explicit_node("a", "class", "A", "a.py"),
            explicit_node("b", "function", "b", "b.py", "L2"),
        ]
        snapshot, encoded, digest = self.normalize({
            "nodes": nodes,
            "edges": [{"source": "a", "target": "external.lib", "relation": "imports"}],
        })
        self.assertEqual(len(snapshot["nodes"]), 2)
        self.assertEqual(snapshot["edges"], [])
        normalize.validate_snapshot(snapshot)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)

    def test_exact_d5_family_omits_two_pathlib_edges_and_preserves_three_valid_edges(self):
        snapshot, _, _ = self.normalize({"nodes": d6_nodes(), "edges": d6_edges()})
        self.assertEqual(len(snapshot["nodes"]), 5)
        self.assertEqual(len(snapshot["edges"]), 3)
        kinds = [edge["kind"] for edge in snapshot["edges"]]
        self.assertEqual(sorted(kinds), ["calls", "contains", "contains"])

    def test_edge_reordering_and_three_runs_are_byte_identical(self):
        graph_a = {"nodes": d6_nodes(), "edges": d6_edges()}
        graph_b = {"nodes": d6_nodes(), "edges": list(reversed(d6_edges()))}
        runs = [self.normalize(graph_a) for _ in range(3)]
        reordered = self.normalize(graph_b)
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(runs[1], runs[2])
        self.assertEqual(runs[0], reordered)
        self.assertEqual(len({run[2] for run in runs}), 1)

    def test_disallowed_unresolved_categories_remain_fail_closed(self):
        nodes = [
            explicit_node("a", "class", "A", "a.py"),
            explicit_node("b", "function", "b", "b.py", "L2"),
        ]
        cases = (
            ({"source": "missing-source", "target": "b", "relation": "calls"}, "missing source only"),
            ({"source": "missing-source", "target": "missing-target", "relation": "calls"}, "both endpoints missing"),
            ({"source": "a", "target": ["missing-target"], "relation": "calls"}, "non-string unresolved target"),
            ({"source": ["missing-source"], "target": "b", "relation": "calls"}, "non-string unresolved source"),
        )
        for edge, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(normalize.GraphOutputError):
                    self.normalize({"nodes": nodes, "edges": [edge]})

    def test_target_or_source_present_raw_but_failed_canonicalization_fails_closed(self):
        good = explicit_node("good", "class", "Good", "good.py")
        bad_target = explicit_node("bad-target", "function", "Bad", "../bad.py")
        with self.assertRaises(normalize.GraphOutputError):
            self.normalize({
                "nodes": [good, bad_target],
                "edges": [{"source": "good", "target": "bad-target", "relation": "calls"}],
            })
        bad_source = explicit_node("bad-source", "class", "Bad", "../bad.py")
        with self.assertRaises(normalize.GraphOutputError):
            self.normalize({
                "nodes": [bad_source, good],
                "edges": [{"source": "bad-source", "target": "good", "relation": "calls"}],
            })

    def test_edge_shape_and_discriminator_are_validated_before_omission(self):
        nodes = [explicit_node("a", "class", "A", "a.py")]
        malformed = (
            7,
            {"source": "a", "relation": "calls"},
            {"source": "a", "target": "external"},
            {"source": "a", "target": "external", "relation": {}},
            {"source": "a", "target": "external", "type": []},
            {"source": "a", "target": "external", "kind": 7},
        )
        for edge in malformed:
            with self.subTest(edge=edge):
                with self.assertRaises(normalize.GraphOutputError):
                    self.normalize({"nodes": nodes, "edges": [edge]})

    def test_raw_node_id_collision_and_ambiguous_kind_mapping_remain_fail_closed(self):
        colliding = [
            explicit_node(1, "class", "A", "a.py"),
            explicit_node("1", "function", "B", "b.py", "L2"),
        ]
        with self.assertRaisesRegex(normalize.GraphOutputError, "raw node id stringification collision"):
            self.normalize({"nodes": colliding, "edges": []})
        with mock.patch.object(normalize, "_d3_compat_node_kind", return_value="class"):
            with self.assertRaisesRegex(normalize.GraphOutputError, "ambiguous missing-discriminator node kind"):
                normalize._missing_discriminator_kind(d4_file_node())

    def test_valid_two_ended_edges_and_d4_file_class_function_mapping_are_unchanged(self):
        graph = {
            "nodes": [d4_file_node(), d4_class_node(), d4_function_node()],
            "edges": [
                {"source": "pkg_a", "target": "pkg_a_a", "relation": "contains"},
                {"source": "pkg_a_a", "target": "pkg_a_f", "relation": "calls"},
            ],
        }
        snapshot, encoded, digest = self.normalize(graph)
        self.assertEqual({node["qualified_name"]: node["kind"] for node in snapshot["nodes"]}, {
            "a.py": "file", "A": "class", "f()": "function",
        })
        self.assertEqual(len(snapshot["edges"]), 2)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
