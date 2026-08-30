from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from graphify_builder import normalize, worker

SHA = "1111111111111111111111111111111111111111"


class D7BWorkerNormalizationBoundaryTests(unittest.TestCase):
    def _execute_with_graph_bytes(
        self,
        graph_bytes: bytes,
        normalize_error: str | None,
    ) -> tuple[int, dict, int, object, dict[str, bool]]:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            product = base / "product"
            wheelhouse = base / "wheelhouse"
            output = base / "output"
            product.mkdir()
            wheelhouse.mkdir()
            manifest = {
                "artifacts": [
                    {
                        "filename": "graphifyy-test.whl",
                        "name": worker.GRAPHIFY_PACKAGE,
                        "sha256": "0" * 64,
                    }
                ]
            }

            def fake_run(command, **kwargs):
                if tuple(command) == worker.EXACT_GRAPHIFY_COMMAND:
                    graph_out = Path(kwargs["env"]["GRAPHIFY_OUT"])
                    graph_out.mkdir(parents=True, exist_ok=True)
                    (graph_out / "graph.json").write_bytes(graph_bytes)
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.object(worker, "assert_runtime"),
                mock.patch.object(worker, "assert_sensitive_environment_absent"),
                mock.patch.object(worker, "assert_network_denied"),
                mock.patch.object(worker, "assert_product_read_only"),
                mock.patch.object(worker, "verify_wheelhouse", return_value=manifest),
                mock.patch.object(worker.subprocess, "run", side_effect=fake_run),
                mock.patch.object(worker, "normalize_graph") as normalize_graph,
            ):
                if normalize_error is None:
                    normalize_graph.side_effect = AssertionError(
                        "normalize_graph must not run for malformed graph.json"
                    )
                else:
                    normalize_graph.side_effect = normalize.GraphOutputError(normalize_error)
                rc = worker.execute(product, SHA, wheelhouse, output)
                health = json.loads((output / "health.json").read_text(encoding="utf-8"))
                call_count = normalize_graph.call_count
                call_args = normalize_graph.call_args
                emitted = {
                    "snapshot": (output / "snapshot.json").exists(),
                    "metadata": (output / "metadata.json").exists(),
                    "complete": (output / ".canonical-emission-complete").exists(),
                }
                return rc, health, call_count, call_args, emitted

    def test_worker_uses_normalize_as_authoritative_compatibility_boundary(self):
        graph = {
            "nodes": [
                {
                    "id": "raw-node",
                    "label": "raw-node",
                    "file_type": "code",
                    "source_file": "src/raw-node.unknown",
                    "source_location": "L1",
                }
            ],
            "edges": [],
        }
        normalize_detail = "normalize boundary rejection: " + ("x" * 5000)

        rc, health, call_count, call_args, emitted = self._execute_with_graph_bytes(
            json.dumps(graph).encode("utf-8"),
            normalize_detail,
        )

        self.assertEqual(call_count, 1)
        self.assertIsNotNone(call_args)
        self.assertEqual(call_args.args[0], graph)
        self.assertEqual(call_args.args[1], SHA)
        self.assertEqual(rc, 1)
        self.assertEqual(health["state"], "incompatible_upstream_output")
        self.assertEqual(
            health["reason_code"],
            "malformed_or_incompatible_graphify_output",
        )
        self.assertEqual(health["detail"], normalize_detail[:4096])
        self.assertEqual(len(health["detail"]), 4096)
        self.assertFalse(any(emitted.values()))
        self.assertNotIn(
            "diagnose_missing_discriminator_nodes",
            Path(worker.__file__).read_text(encoding="utf-8"),
        )

        malformed = self._execute_with_graph_bytes(b"{not-json", None)
        malformed_rc, malformed_health, malformed_calls, _, malformed_emitted = malformed
        self.assertEqual(malformed_rc, 1)
        self.assertEqual(malformed_calls, 0)
        self.assertEqual(malformed_health["state"], "incompatible_upstream_output")
        self.assertEqual(
            malformed_health["reason_code"],
            "malformed_or_incompatible_graphify_output",
        )
        self.assertEqual(malformed_health["detail"], "Graphify graph.json malformed")
        self.assertFalse(any(malformed_emitted.values()))


if __name__ == "__main__":
    unittest.main()
