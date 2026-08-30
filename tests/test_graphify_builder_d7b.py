from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from graphify_builder import normalize

SYNTHETIC_SHA = "1111111111111111111111111111111111111111"
PINNED_SHA = "8fd669336b36064e842252d69fb4016cc526a9d4"


def explicit(
    node_id: str,
    kind: str = "class",
    label: str | None = None,
    path: str | None = None,
    line: int = 1,
) -> dict:
    return {
        "id": node_id,
        "type": kind,
        "label": label or node_id,
        "source_file": path or f"src/{node_id}.hpp",
        "source_location": f"L{line}",
    }


def cpp_field(
    node_id: str = "Widget::value",
    *,
    label: str = "value",
    path: str = "src/widget.hpp",
    origin: str = "ast",
    file_type: str = "code",
    location: str = "L7",
) -> dict:
    return {
        "_origin": origin,
        "file_type": file_type,
        "id": node_id,
        "label": label,
        "source_file": path,
        "source_location": location,
    }


def defines_field(parent: str, target: str = "Widget::value") -> dict:
    return {
        "source": parent,
        "target": target,
        "relation": "defines",
        "context": "field",
    }


class D7BDeterministicCppSourceAstClassificationTests(unittest.TestCase):
    def normalize(self, graph: dict):
        with tempfile.TemporaryDirectory() as d:
            return normalize.normalize_graph(graph, SYNTHETIC_SHA, Path(d))

    def assert_missing_discriminator(self, graph: dict) -> None:
        with self.assertRaisesRegex(
            normalize.GraphOutputError,
            "missing node discriminator inventory",
        ):
            self.normalize(graph)

    def test_exact_cpp_source_ast_shape_classifies_as_existing_field_kind_through_normalize_graph(self):
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                explicit("reader", "function", "reader", "src/reader.cpp", 3),
                cpp_field(),
            ],
            "edges": [
                defines_field("Widget"),
                {
                    "source": "reader",
                    "target": "Widget::value",
                    "relation": "calls",
                    "context": "call",
                },
            ],
        }

        snapshot, _, _ = self.normalize(graph)

        field_nodes = [
            node
            for node in snapshot["nodes"]
            if node["qualified_name"] == "value"
        ]
        self.assertEqual(len(field_nodes), 1)
        self.assertEqual(field_nodes[0]["kind"], "field")
        self.assertEqual(field_nodes[0]["path"], "src/widget.hpp")
        self.assertEqual(field_nodes[0]["start_line"], 7)
        self.assertEqual(field_nodes[0]["end_line"], 7)

    def test_changing_material_source_ast_origin_fails_closed(self):
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                cpp_field(origin="source"),
            ],
            "edges": [defines_field("Widget")],
        }
        self.assert_missing_discriminator(graph)

    def test_cpp_suffix_and_code_language_shape_without_ast_relationship_is_insufficient(self):
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                cpp_field(),
            ],
            "edges": [],
        }
        self.assert_missing_discriminator(graph)

    def test_defines_field_relation_without_cpp_source_ast_evidence_is_insufficient(self):
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                cpp_field(path="scripts/widget.ps1"),
            ],
            "edges": [defines_field("Widget")],
        }
        self.assert_missing_discriminator(graph)

    def test_name_and_casing_alone_are_insufficient(self):
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                cpp_field(
                    label="FIELD_VALUE",
                    path="notes/value.txt",
                    origin="source",
                    file_type="metadata",
                ),
            ],
            "edges": [],
        }
        self.assert_missing_discriminator(graph)

    def test_ambiguous_structural_source_ast_evidence_fails_closed(self):
        graph = {
            "nodes": [
                explicit("WidgetA", "class", "WidgetA", "src/a.hpp"),
                explicit("WidgetB", "class", "WidgetB", "src/b.hpp"),
                cpp_field(),
            ],
            "edges": [
                defines_field("WidgetA"),
                defines_field("WidgetB"),
            ],
        }
        self.assert_missing_discriminator(graph)

    def test_explicit_discriminator_precedence_remains_unchanged(self):
        node = {
            **cpp_field(),
            "type": "function",
        }
        graph = {
            "nodes": [
                explicit("Widget", "class", "Widget", "src/widget.hpp"),
                node,
            ],
            "edges": [defines_field("Widget")],
        }

        snapshot, _, _ = self.normalize(graph)

        explicit_node = next(
            item
            for item in snapshot["nodes"]
            if item["qualified_name"] == "value"
        )
        self.assertEqual(explicit_node["kind"], "function")

    def test_d7a_pinned_omission_counts_and_gate_are_unchanged(self):
        expected = {
            "python_rationale": 46,
            "json_code": 31,
            "json_concept": 10,
            "sourceless_reference_stub_family_b": 255,
        }
        self.assertEqual(normalize._D7A_PINNED_PRODUCT_SHA, PINNED_SHA)
        self.assertEqual(normalize._D7A_PINNED_COUNTS, expected)
        normalize._assert_d7a_pinned_counts(expected)
        drift = {**expected, "json_code": 30}
        with self.assertRaisesRegex(
            normalize.GraphOutputError,
            "D7-A pinned omission count drift",
        ):
            normalize._assert_d7a_pinned_counts(drift)

    def test_later_sourced_code_families_remain_fail_closed(self):
        for suffix in (".ps1", ".mjs", ".py"):
            with self.subTest(suffix=suffix):
                graph = {
                    "nodes": [
                        explicit("Widget", "class", "Widget", "src/widget.hpp"),
                        cpp_field(path=f"src/value{suffix}"),
                    ],
                    "edges": [defines_field("Widget")],
                }
                self.assert_missing_discriminator(graph)

    def test_raw_ordering_produces_identical_canonical_bytes_and_digest(self):
        nodes = [
            explicit("Widget", "class", "Widget", "src/widget.hpp"),
            explicit("Gadget", "class", "Gadget", "src/gadget.hpp", 2),
            cpp_field(),
            cpp_field(
                "Gadget::count",
                label="count",
                path="src/gadget.cpp",
                location="L9",
            ),
        ]
        edges = [
            defines_field("Widget"),
            defines_field("Gadget", "Gadget::count"),
        ]
        graph_a = {"nodes": nodes, "edges": edges}
        graph_b = {"nodes": list(reversed(nodes)), "edges": list(reversed(edges))}

        snapshot_a, payload_a, digest_a = self.normalize(graph_a)
        snapshot_b, payload_b, digest_b = self.normalize(graph_b)

        self.assertEqual(snapshot_a, snapshot_b)
        self.assertEqual(payload_a, payload_b)
        self.assertEqual(digest_a, digest_b)


if __name__ == "__main__":
    unittest.main()
