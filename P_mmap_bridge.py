"""
Zero-Copy file ingestion streamer (memory-mapped I/O)
Allows to bypass kernel to user space memory copying vy mapping the binary telemetry
logs directly into virtual memory and paaing the pointer to C"""

import os
import mmap
import ctypes
import time
import struct
import sys

class ProcessTelemetry(ctypes.Structure):
    """Binds directly to our native C structure tracking system load. Size: 32 Bytes"""
    _fields_ = [
        ("pid", ctypes.c_uint64),
        ("ram_bytes", ctypes.c_uint64),
        ("thread_count", ctypes.c_uint64),
        ("open_handles", ctypes.c_uint64)
    ]
#resolve os binaries
plat = sys.platform
if "win32" in plat:
    bin_file = "P_native_core.dll"
elif "darwin" in plat:
    bin_file = "P_native_core.dylib"
else:
    bin_file = "P_native_core.so"
        
target_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), bin_file)
if not os.path.isfile(target_path):
    raise RuntimeError(f"Missing essential C engine binary: {target_path}. Please compile first.")
        
core_engine = ctypes.CDLL(target_path)

# Enforce strict FFI signatures
core_engine.process_telemetry_stream.argtypes = [
    ctypes.POINTER(ProcessTelemetry), #the mapped memory pointer
    ctypes.c_int32,                   #total rows
    ctypes.POINTER(ctypes.c_uint64),  #output buffer
    ctypes.c_int32,                   #max alerts
    ctypes.POINTER(ctypes.c_int32),   #alert count tracker
    ctypes.POINTER(ctypes.c_uint64),  #dynamic whitelist
    ctypes.c_int32                    #whitelist size
]

core_engine.process_telemetry_stream.restype = ctypes.c_int32

def zero_copy_log_ingestion(filepath: str, whitelist_pids: list):
    """ Maps massive binary telemetry file directly to Ram and executes .
    Achieves O(1) space complexity """

    if not os.path.exists(filepath):
        print(f"[-] Target telemetry log not found: {filepath}")
        return

    file_size = os.path.getsize(filepath)
    if file_size == 0 or file_size % ctypes.sizeof(ProcessTelemetry) != 0:
        print("[-] Invalid file size. Must be a multiple of 32 bytes.")
        return

    total_rows = file_size // ctypes.sizeof(ProcessTelemetry)
    print(f"[*] Target Log: {filepath} | {file_size / (1024*1024):.2f} MB | {total_rows:,} Rows")

    #output buffer and dynamic whitelist (patch) apply hard cap for O(1) space complexity
    max_alerts=1024
    whitelist_size = len(whitelist_pids)
    whitelist_c_array = (ctypes.c_uint64 * whitelist_size)(*whitelist_pids)
    out_alerts = (ctypes.c_uint64 * max_alerts)()
    alert_total = ctypes.c_int32(0)

    try:
        with open(filepath, "r+b") as f:
            #map physical disk to Virtual RAM
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:  #allows usage of .from_buffer
                #direct pointer creation (patch)
                raw_buffer = (ProcessTelemetry * total_rows).from_buffer(mm)
                
                start = time.perf_counter()
                exit_code = core_engine.process_telemetry_stream(
                    raw_buffer,
                    total_rows,
                    out_alerts,
                    max_alerts,
                    ctypes.byref(alert_total),
                    whitelist_c_array,
                    whitelist_size
                )

                end = time.perf_counter()
                #destroy exported memory view pointers to prevent winerror
                del raw_buffer

                if exit_code < 0:
                    raise OSError(f"C-Engine crashed! Code: {exit_code}")
            
            mm.close()
    except Exception as e:
        print(f"[CRITICAL] Memory Mapping failed: {e}")
        return
    
    zlatency = (end - start) * 1000

    valid_alerts = [out_alerts[x] for x in range(min(alert_total.value, max_alerts))]
    print(" ⚡ ZERO-COPY DISK-TO-CPU EXECUTION METRICS ⚡ ")
    print("-" * 60)
    print(f"Size of file processed   : {file_size / (1024*1024):.2f} MB")
    print(f"Total Rows Audited       : {total_rows:,}")
    print(f"Disk-to-C Latency        : {zlatency:.4f} ms")
    print(f"Detected Threats         : {len(valid_alerts)}")
    if len(valid_alerts) > 0:
        print(f"Critical PIDs         : {valid_alerts[:5]} ...")



if __name__=="__main__":
    test_log = "massive_sensor_dump.bin"
    print("[*] Generating synthetic 10MB binary log (300,000 telemetry rows)...")
    
    with open(test_log, "wb") as f:
        #benign packet 
        benign_struct = struct.pack("QQQQ", 500, 100000000, 10, 50)
        f.write(benign_struct * 299999) 
        
        #single malicious packet hidden at the end (PID 999, 50MB RAM, 0 Threads, 15 Handles)
        malicious_struct = struct.pack("QQQQ", 999, 50000000, 0, 15)
        f.write(malicious_struct)
        
    dynamic_whitelist = [4, 76, 1001, 1002]
    
    #run
    zero_copy_log_ingestion(test_log, dynamic_whitelist)

    if os.path.exists(test_log):
        time.sleep(0.1)
        try:
            os.remove(test_log)
        except OSError as e:
             print(f"[WARNING] OS still holding file lock, please delete manually: {e}")

    



