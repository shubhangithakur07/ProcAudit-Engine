import unittest
import numpy as np
import importlib.util
import sys
import os

#Dynamic import(because our file has special characters! had to find a workaround)
spec = importlib.util.spec_from_file_location("live_audit", "./(P)live_system_audit.py")
live_audit = importlib.util.module_from_spec(spec)
sys.modules["live_audit"] = live_audit
spec.loader.exec_module(live_audit)

audit_live_kernel_vectors = live_audit.audit_live_kernel_vectors #shortcut pointer
class TestVectorSecurityEngine(unittest.TestCase):
#ensuring no leaks
   def setUp(self):
    #setup for simulation testing
    self.MB = 1024 * 1024
    self.FIFTY_MB = 50.0 * self.MB

   def test_whitelist_mitigation(self):
    """PROVE: PID 76 and PID 4 do not trigger false alerts despite zero threads."""
    
    #[PID, RAM_Bytes,Thread_Count, Open_Handles]
    mock_krnl=np.array([
            [76.0, 35.0 * self.MB, 0.0, 20.0],  # Registry (Benign Exception)
            [4.0,  10.0 * self.MB, 0.0, 450.0]  # Kernel Core (Benign Exception)
        ], dtype=np.float64)
    result = audit_live_kernel_vectors(mock_krnl)
    self.assertEqual(len(result["orphaned_stealth_suspects"]), 0)
    self.assertEqual(result["compromise_percentage"], 0.0)

   def test_stealth_threat_isolation(self):
    """PROVE:An unwhitelised process with 0 threads and active memory is intercepted."""
    mock_krnl = np.array([
            [999.0, 85.0 * self.MB, 0.0, 15.0]  #orphaned stealth threat injected
        ], dtype=np.float64)
    result=audit_live_kernel_vectors(mock_krnl)
    self.assertIn(999, result["orphaned_stealth_suspects"])
    self.assertEqual(result["compromise_percentage"], 100.0)

   def test_resource_exhaustion_isolation(self):
        """PROVE: A process with normal thread count but excessive handles is flagged."""
        mock_krnl = np.array([
            [101.0, 15.0 * self.MB, 4.0, 12000.0]  #highly abnormal number of open handles even though no of active threads is just 4.0
        ], dtype=np.float64)
        
        result = audit_live_kernel_vectors(mock_krnl)
        
        self.assertIn(101, result["resource_exhaustion_suspects"])  
        self.assertEqual(result["compromise_percentage"], 100.0)   

if __name__=="__main__":
  unittest.main()


