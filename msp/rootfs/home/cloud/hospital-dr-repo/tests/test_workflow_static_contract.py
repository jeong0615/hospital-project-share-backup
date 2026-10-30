import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class WorkflowStaticContractTest(unittest.TestCase):
    def read(self, relative_path):
        return (ROOT / relative_path).read_text()

    def test_chatops_failback_uses_complete_entrypoint(self):
        source = self.read("operations/chatops/chatops_core.py")
        self.assertIn('os.path.join(script_root, "web_db_failback.sh")', source)
        self.assertNotIn('os.path.join(script_root, "full_failback.sh")', source)

    def test_wrapper_preserves_db_doc_order_before_dns(self):
        source = self.read("operations/failover/full_failback.sh")
        db_call = source.index('"${DB_DIR}/db_failback_to_onprem.sh"')
        doc_call = source.index('"${DB_DIR}/doc_failback_sync.sh"')
        dns_call = source.index('"${FAILOVER_DIR}/failback.sh"')
        self.assertLess(db_call, doc_call)
        self.assertLess(doc_call, dns_call)
        self.assertIn('RUN_DB_FAILBACK:-false', source)
        self.assertIn('RUN_DOC_FAILBACK:-false', source)

    def test_repo_contains_chatops_launchers_and_run_demo(self):
        self.assertTrue((ROOT / "infra/terraform/run_demo.sh").is_file())
        self.assertTrue((ROOT / "infra/terraform/full_failover.sh").is_file())
        self.assertTrue((ROOT / "infra/terraform/web_db_failback.sh").is_file())

    def test_failback_wrapper_has_fail_safe_lock_and_shell_mode(self):
        source = self.read("operations/failover/full_failback.sh")
        self.assertIn("set -euo pipefail", source)
        self.assertIn('flock', self.read("operations/failover/failback.sh"))
        self.assertIn("pipeline_lock", self.read("operations/chatops/chatops_core.py"))

    def test_timing_boundaries_exist_for_ordered_stages(self):
        sources = {
            "failover": self.read("operations/failover/full_failover.sh"),
            "failback": self.read("operations/failover/full_failback.sh"),
            "db": self.read("operations/db/db_failback_to_onprem.sh"),
            "doc": self.read("operations/db/doc_failback_sync.sh"),
        }
        for source in sources.values():
            self.assertIn("dr_timing_start", source)
            self.assertIn("dr_timing_end", source)


if __name__ == "__main__":
    unittest.main()
