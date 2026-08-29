from __future__ import annotations

import unittest

from graphify_builder import missing_node_diagnostic


class MissingNodeSemanticDiagnosticTests(unittest.TestCase):
    def test_complete_partition_relations_provenance_and_collisions(self):
        graph = {
            "nodes": [
                {"id": "parent", "type": "class", "label": "Parent", "file_type": "code", "source_file": "a.hpp", "source_location": "L1"},
                {"_origin": "ast", "file_type": "code", "id": "field", "label": "field_", "source_file": "a.hpp", "source_location": "L2"},
                {"_origin": "ast", "file_type": "code", "id": "External", "label": "External", "source_file": "", "source_location": ""},
            ],
            "edges": [
                {"source": "parent", "target": "field", "relation": "defines", "context": "field", "source_file": "a.hpp"},
                {"source": "parent", "target": "External", "relation": "references", "context": "field", "source_file": "a.hpp"},
            ],
        }
        report = missing_node_diagnostic.diagnose_missing_discriminator_nodes(graph)
        self.assertEqual(report["total"], 2)
        self.assertEqual(report["stringification_collision_groups"], 0)
        self.assertEqual([family["count"] for family in report["families"]], [1, 1])
        by_shape = {family["source_location_shape"]: family for family in report["families"]}
        line = by_shape["line"]
        text = by_shape["text"]
        self.assertEqual(line["origin_values"], {"ast": 1})
        self.assertEqual(line["file_type_values"], {"code": 1})
        self.assertEqual(line["source_file_presence"], {"nonempty": 1})
        self.assertEqual(line["source_location_presence"], {"nonempty": 1})
        self.assertEqual(line["incoming_relation_context"], [["defines", "field", 1]])
        self.assertEqual(line["outgoing_relation_context"], [])
        self.assertEqual(line["structural_parent_relations"], [["defines", "field", 1]])
        self.assertEqual(text["source_file_presence"], {"empty": 1})
        self.assertEqual(text["source_location_presence"], {"empty": 1})
        self.assertEqual(text["incoming_relation_context"], [["references", "field", 1]])
        self.assertEqual(text["incoming_edge_source_suffixes"], {".hpp": 1})
        self.assertEqual(text["same_label_sourced_candidate_counts"], {"0": 1})
        self.assertRegex(line["inventory_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(text["inventory_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(report["inventory_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
