"""
 Security Engine Unit Tests
Automated validation suite for the low-level process auditing pipeline.
Developer: Shubhangithakur07
"""

import time
import unittest
import numpy as np
from P_bridge import run_audit as execute_native_core_audit

telemetry_dtype = np.dtype([
    ("pid", np.uint64),
    ("ram_bytes", np.uint64),
    ("thread_count", np.uint64),
    ("open_handles", np.uint64)
])
class TestNativeSecurityEngine(unittest.TestCase):

    def setUp(self):
        """Initialize reusable mock variables for the test lifecycle."""
        self.rogue_pid = 999
        self.kernel_pid = 76
        self.whitelist = np.array([4, 76, 1001, 1002], dtype=np.uint64) #as bridge now expects array for dynamic whitelisting

    def test_stealth_threat_detection(self):
        # Target: Orphan process holding memory space while reporting 0 threads
        payload = np.array([(self.rogue_pid, 500000, 0, 10)], dtype=telemetry_dtype)
        flagged, _ = execute_native_core_audit(payload, self.whitelist)
        
        # Verify the pipeline successfully caught the target anomalous PID
        self.assertIn(self.rogue_pid, flagged)

    def test_kernel_whitelist_bypass(self):
        # Target: Idle system infrastructure processes using memory
        payload = np.array([(self.kernel_pid, 1200000, 0, 45)], dtype=telemetry_dtype)
        flagged, _ = execute_native_core_audit(payload, self.whitelist)
        
        # Core infrastructure must be filtered out cleanly
        self.assertEqual(len(flagged), 0)

    def test_empty_payload_safeguard(self):
        # Border case: Absolute empty array stream submitted to the ctypes boundary
        empty_matrix = np.array([], dtype=telemetry_dtype)
        flagged, _ = execute_native_core_audit(empty_matrix, self.whitelist)
        
        self.assertEqual(len(flagged), 0)
    def test_c_engine_latency_constraint(self):
        """PROVE: The C-Engine and ctypes bridge process 10,000 records in < 5.0ms."""
        test_rows= 10001
        #generate 10,000 safe processes dynamically
        payload = np.zeros(test_rows, dtype=telemetry_dtype)
        # populate benign processes in bulk
        payload['pid'] = np.arange(1000, 1000 + test_rows, dtype=np.uint64)
        payload['ram_bytes'] = 1024000
        payload['thread_count'] = 2
        payload['open_handles'] = 50
        
        #hide exactly one rogue malware process at the very end
        payload[10000] = (8888, 5000000, 0, 0)
        
        flagged,engine_latency = execute_native_core_audit(payload, self.whitelist)
    
        #lie detectors and strict performance bounds
        self.assertIn(8888, flagged)
        self.assertLess(engine_latency, 5.0, f"Engine performance degraded! Took {engine_latency:.4f} ms")    #will use ctypes if absolute necessity of maximum optimisation 

if __name__ == "__main__":
    print("[RUNNING] Executing Test Suite validations...")
    unittest.main(verbosity=2)
