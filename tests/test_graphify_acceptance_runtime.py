from __future__ import annotations

import importlib.util
import unittest


class GraphifyAcceptanceRuntimeRedTests(unittest.TestCase):
    def test_i10_0085_exact_runtime_capability_exists(self):
        spec = importlib.util.find_spec("graphify_acceptance_runtime")
        self.assertIsNotNone(
            spec,
            "I10-0085 RED: exact in-job Graphify acceptance runtime acquisition capability is not implemented",
        )


if __name__ == "__main__":
    unittest.main()
