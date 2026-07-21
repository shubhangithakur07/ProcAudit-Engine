"""
Python Telemetry Core Harness
Interoperability wrapper using ctypes for low-level process validation.
Developer: Shubhangi Thakur
"""

import os
import sys
import ctypes
import time
import numpy as np
import numpy.ctypeslib as npct


telemetry_dtype = np.dtype([
        ("pid", np.uint64),
        ("ram_bytes", np.uint64),
        ("thread_count", np.uint64),
        ("open_handles", np.uint64)
    ])
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
    raise RuntimeError(f"Missing essential C engine binary: {target_path}.Please compile first.")
        
# Bind to low-level engine (once)
core_engine = ctypes.CDLL(target_path)
arraytelemetry = npct.ndpointer(dtype=telemetry_dtype, ndim=1, flags='C_CONTIGUOUS')
arrayuint64 = npct.ndpointer(dtype=np.uint64, ndim=1, flags='C_CONTIGUOUS')
    
# Enforce C function prototypes explicitly(dynmaic whitelisting update)
core_engine.process_telemetry_stream.argtypes = [
    arraytelemetry,#dataset pointer
    ctypes.c_int32,#total rows
    arrayuint64,#alert_buffer pointer
    ctypes.c_int32,   #max alerts (new parameter)
    ctypes.POINTER(ctypes.c_int32),#total_alerts pointer
    arrayuint64, # whitelist mask pointer
    ctypes.c_int32            #whitelist size       

]
core_engine.process_telemetry_stream.restype = ctypes.c_int32


def run_audit(numpy_telemetry_array, numpy_whitelist_array):
    if numpy_telemetry_array.size == 0:
        return np.array([], dtype=np.uint64), 0.0

    
    total_elements = numpy_telemetry_array.shape[0]
    whitelist_size = numpy_whitelist_array.shape[0]
    # Pre-allocate output buffer in numpy
    out_alerts =np.zeros(total_elements, dtype=np.uint64)
    alert_total = ctypes.c_int32(0)

    startc=time.perf_counter()
   
    # Invoke runtime engine pipeline
    exit_code = core_engine.process_telemetry_stream(
        numpy_telemetry_array, 
        total_elements, 
        out_alerts,
        total_elements,       #(max_alerts)
        ctypes.byref(alert_total),
        numpy_whitelist_array,
        whitelist_size

    )

    endc=time.perf_counter()
    clatency=(endc-startc)*1000
    
    if exit_code < 0:
        raise OSError(f"Low-level C processing pipeline broken. Code: {exit_code}")
        
    # Extract only valid hits from buffer slice
    valid_alerts = out_alerts[:alert_total.value]
    return valid_alerts,clatency

if __name__ == "__main__":
    #stress testing
    print("Generating 1,00,000 row high-density stress test matrix...")
    test_rows=100000
    test_telemetry = np.zeros(test_rows, dtype=telemetry_dtype)
    
    test_telemetry['pid'] = np.arange(1000, 1000 + test_rows, dtype=np.uint64)
    test_telemetry['ram_bytes'] = np.random.randint(1000, 50000000, size=test_rows, dtype=np.uint64)
    test_telemetry['thread_count'] = np.random.randint(1, 100, size=test_rows, dtype=np.uint64)
    test_telemetry['open_handles'] = np.random.randint(10, 500, size=test_rows, dtype=np.uint64)

    dwhitelist = np.array([4, 76, 1001, 1002], dtype=np.uint64)
    test_telemetry[6000] = (999, 85000000, 0, 15)   # Rogue process (0 threads, high RAM)
    test_telemetry[8000] = (1005, 50000, 0, 2)     # Rogue process
    test_telemetry[9900] = (76, 45000000, 0, 120)   # Whitelisted Kernel (0 threads, high RAM)

    

    
    
    try:
        _ = run_audit(test_telemetry[:10], dwhitelist)
        results,c_latency = run_audit(test_telemetry,dwhitelist)
        
        print(" ⚡ NATIVE C-ENGINE TELEMETRY AUDIT ⚡ ")
        print(f"[SUCCESS] Interop Pipeline Active.")
        print(f"Caught Malicious PIDs : {results}")
        print(f" Pure C Engine Latency    : {c_latency:.4f} ms")
    except Exception as e:
        print(f"[FAILURE] Test sequence aborted: {e}")


