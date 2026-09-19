import importlib.util
import unittest
from pathlib import Path

import numpy as np

spec = importlib.util.spec_from_file_location("privacy_files", Path(__file__).parents[1] / "privacy-files-classifier.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class PrivacyFilesTest(unittest.TestCase):
    def test_auc_ties_and_inverted_signal(self):
        self.assertEqual(privacy.auc([0, 0, 0, 0], [0, 0, 1, 1]), 0.5)
        self.assertEqual(privacy.auc([1, 1, 0, 0], [0, 0, 1, 1]), 0)
        self.assertEqual(privacy.auc([0, 0, 1, 1], [0, 0, 1, 1]), 1)

    def test_window_directions_silence_and_bounds(self):
        rows = [(10.1, 50000, 27101, 50, "S"), (10.2, 27101, 50000, 100, "."),
                (12.0, 50000, 27101, 999, ".")]
        x = privacy.features(rows, 27101, 10, 2)
        self.assertEqual(x.shape, (2, 15))
        self.assertEqual(x[0, :4].tolist(), [1, 1, 50, 100])
        self.assertEqual(x[0, 13], 1)
        self.assertTrue((x[1] == 0).all())

    def test_clustered_gate_rejects_signal_and_requires_independent_runs(self):
        labels = np.asarray([0, 0, 1, 1])
        identical = [(np.ones((4, 2)), labels) for _ in range(8)]
        result = privacy.evaluate(identical, identical, bootstrap=100)
        self.assertTrue(result["ok"])
        self.assertEqual(result["separability_upper_97_5"], 0.5)
        signal = [(np.asarray([[0], [0], [10], [10]]), labels) for _ in range(8)]
        self.assertFalse(privacy.evaluate(signal, signal, bootstrap=100)["ok"])
        with self.assertRaisesRegex(ValueError, "independent"):
            privacy.evaluate(identical[:1], identical, bootstrap=100)


if __name__ == "__main__":
    unittest.main()

