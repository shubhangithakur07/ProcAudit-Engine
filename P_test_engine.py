"""
 Security Engine Unit Tests
Automated validation suite for the low-level process auditing pipeline.
Developer: Shubhangithakur07
"""

import os
import time
import unittest
from P_bridge import run_audit as execute_native_core_audit

class TestNativeSecurityEngine(unittest.TestCase):

    def setUp(self):
        """Initialize reusable mock variables for the test lifecycle."""
        self.rogue_pid = 999
        self.kernel_pid = 76

    def test_stealth_threat_detection(self):
        # Target: Orphan process holding memory space while reporting 0 threads
        payload = [[self.rogue_pid, 500000, 0, 10]]
        flagged = execute_native_core_audit(payload)
        
        # Verify the pipeline successfully caught the target anomalous PID
        self.assertIn(self.rogue_pid, flagged)

    def test_kernel_whitelist_bypass(self):
        # Target: Idle system infrastructure processes using memory
        payload = [[self.kernel_pid, 1200000, 0, 45]]
        flagged = execute_native_core_audit(payload)
        
        # Core infrastructure must be filtered out cleanly
        self.assertEqual(len(flagged), 0)

    def test_empty_payload_safeguard(self):
        # Border case: Absolute empty array stream submitted to the ctypes boundary
        empty_matrix = []
        flagged = execute_native_core_audit(empty_matrix)
        
        self.assertEqual(flagged, [])
    def test_c_engine_latency_constraint(self):
        """PROVE: The C-Engine and ctypes bridge process 10,000 records in <25ms."""
        
        #Generate 10,000 safe processes dynamically using a List Comprehension
        payload = [[1000 + i, 1024000, 2, 50] for i in range(10000)]
        
        #Hide exactly one rogue malware process at the very end
        payload.append([8888, 5000000, 0, 0])
        start = time.perf_counter()
        #Fire the 10,001 items across the C-Bridge
        flagged = execute_native_core_audit(payload)
        end = time.perf_counter()
        latency = (end - start) * 1000
        
        #The Lie Detectors
        self.assertIn(8888, flagged)
        self.assertLess(latency, 25.0, f"Engine performance degraded! Took {latency:.4f} ms")    

if __name__ == "__main__":
    print("[RUNNING] Executing Test Suite validations...")
    unittest.main(verbosity=2)
