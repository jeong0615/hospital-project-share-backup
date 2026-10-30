import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).parents[1] / "operations" / "db" / "dr_timing.sh"


class DrTimingHelperTest(unittest.TestCase):
    def test_monotonic_metrics_are_emitted_without_zabbix(self):
        with tempfile.TemporaryDirectory() as directory:
            timing_file = Path(directory) / "timing.jsonl"
            script = (
                f"source {HELPER}; "
                "start=$(dr_timing_start test_phase); "
                "sleep 0.01; "
                "dr_timing_end test_phase \"$start\""
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env={**os.environ, "DR_TIMING_FILE": str(timing_file)},
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("[METRIC] test_phase_started_at=", result.stderr)
            self.assertIn("[METRIC] test_phase_duration_ms=", result.stderr)
            records = [json.loads(line) for line in timing_file.read_text().splitlines()]
            self.assertEqual([record["event"] for record in records], [
                "started_at",
                "finished_at",
                "duration_ms",
                "duration_sec",
            ])
            self.assertGreaterEqual(records[2]["value"], 0)

    def test_invalid_clock_does_not_fail_the_workflow(self):
        result = subprocess.run(
            ["bash", "-c", f"source {HELPER}; dr_timing_end bad_phase invalid"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("[METRIC] bad_phase_duration_unavailable=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
