"""
 Python Telemetry Core Harness
Interoperability wrapper using ctypes for low-level process validation.
Developer: Shubhangi Thakur
"""

import os
import sys
import ctypes


class ProcessTelemetry(ctypes.Structure):
    """Binds directly to our native C structure tracking system load."""
    _fields_ = [
        ("pid", ctypes.c_uint64),
        ("ram_bytes", ctypes.c_double),
        ("thread_count", ctypes.c_uint64),
        ("open_handles", ctypes.c_uint64)
    ]
# Resolve OS-specific binaries dynamically
plat = sys.platform
if "win32" in plat:
     bin_file = "P_native_core.dll"
elif "darwin" in plat:
     bin_file = "P_native_core.dylib"
else:
    bin_file = "P_native_core.so"
        
binary_dir = os.path.dirname(os.path.abspath(__file__))
target_path = os.path.join(binary_dir, bin_file)
    
if not os.path.isfile(target_path):
    raise RuntimeError(f"Missing essential C engine binary: {target_path}")
        
# Bind to low-level engine (once)
core_engine = ctypes.CDLL(target_path)
    
# Enforce C function prototypes explicitly
core_engine.process_telemetry_stream.argtypes = [
    ctypes.POINTER(ProcessTelemetry),
    ctypes.c_int32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_int32,   #max alerts (new parameter)
    ctypes.POINTER(ctypes.c_int32)
]
core_engine.process_telemetry_stream.restype = ctypes.c_int32
def run_audit(mock_data_list):
    if not mock_data_list:
        return []

    
    total_elements = len(mock_data_list)
    
    # Allocate and populate flat memory space for the struct array
    telemetry_array = (ProcessTelemetry * total_elements)()
    for i, data in enumerate(mock_data_list):
        telemetry_array[i] = ProcessTelemetry(
            pid=int(data[0]), 
            ram_bytes=float(data[1]), 
            thread_count=int(data[2]), 
            open_handles=int(data[3])
        )
    
    # Pre-allocate output buffer and tracking variable
    out_alerts = (ctypes.c_uint64 * total_elements)()
    alert_total = ctypes.c_int32(0)
    
    # Invoke runtime engine pipeline
    exit_code = core_engine.process_telemetry_stream(
        telemetry_array, 
        total_elements, 
        out_alerts,
        total_elements,       #(max_alerts)
        ctypes.byref(alert_total)
    )
    
    if exit_code < 0:
        raise OSError(f"Low-level C processing pipeline broken. Code: {exit_code}")
        
    # Extract only valid hits from buffer slice
    return [out_alerts[x] for x in range(alert_total.value)]

if __name__ == "__main__":
    # Rapid end-to-end integration test
    test_telemetry = [
        [76, 45000000.0, 0, 120],  # Kernel PID (Should be ignored)
        [999, 85000000.0, 0, 15]   # Rogue process (Should be caught)
    ]
    
    try:
        results = run_audit(test_telemetry)
        print(f"[SUCCESS] Interop Pipeline Active. Caught PIDs: {results}")
    except Exception as e:
        print(f"[FAILURE] Test sequence aborted: {e}")
