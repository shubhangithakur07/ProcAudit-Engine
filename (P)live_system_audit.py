import numpy as np
import psutil
import sys
import os
import json
from datetime import datetime
import time

def capture_and_normalize_kernel_state() -> np.ndarray:
    """
    Hooks into the live OS process table, sanitizes volatile system states,
    and returns a structured 2D float64 matrix for vector threat scanning.
    
    Matrix Structural Format:
    [ Process_ID, Resident_Set_Size_Bytes, Total_Threads, Active_File_Handles ]
    """
    normalised_rows=[] #volatile buffer to collect process information rows one by one before transforming the entire batch into a rigid numerical matrix.
    
    #fix: request files in bulk to prevent syscall looping which slows down process or  melts cpu 
    attrs = ['pid', 'memory_info', 'num_threads', 'num_handles' if sys.platform == 'win32' else 'open_files']
        
    # Querying the active kernel thread table for every running application
    for process in psutil.process_iter(attrs):
        try:
            # Extractimg basic kernel attributes
            pid = int(process.info.get('pid', 0))
            
            # Memory RSS (Resident Set Size): The physical RAM allocated to this process
            mem_info = process.info.get('memory_info')
            rss = int(mem_info.rss) if mem_info is not None else 0
            
            threads = int(process.info.get('num_threads') or 0)
            
            try:
                raw_handles = process.info.get('num_handles' if sys.platform == 'win32' else 'open_files')
                
                if sys.platform == 'win32':
                    # Defensive Shield: If Windows returns a list/tuple etc instead of an integer, count its elements
                    if isinstance(raw_handles, (list, tuple, dict, set)):
                        open_handles = len(raw_handles)
                    else:
                        open_handles = int(raw_handles) if raw_handles is not None else 0
                else:
                    # linux or macOS
                    open_handles = len(raw_handles) if raw_handles is not None else 0
                    
            except (psutil.AccessDenied, AttributeError, TypeError):
                open_handles = 0
                
            normalised_rows.append([pid, rss, threads, open_handles])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Changed from float64 to uint64 for alignment and space optimization
    return np.array(normalised_rows, dtype=np.uint64)


def audit_live_kernel_vectors(os_matrix: np.ndarray) -> dict:
    """
    Executes O(1) vectorized matrix analysis to detect threats,
    while whitelisting benign system processes to prevent false alerts.
    """
    pids         = os_matrix[:, 0]
    ram_bytes    = os_matrix[:, 1]
    thread_counts = os_matrix[:, 2]
    handle_counts = os_matrix[:, 3]
    
    MB_FACTOR = 1024 * 1024
    FIFTY_MB  = 50 * MB_FACTOR
    
    # VECTOR WHITELIST MASK
    # Explicitly track and exclude core kernel (4) and Registry container (76)
    is_legitimate_system_exception = (pids == 4) | (pids == 76)
    
    # Apply bitwise NOT (~) to bypass whitelisted exceptions automatically
    resource_hog_mask = (handle_counts > 3000) & (ram_bytes < FIFTY_MB) & (~is_legitimate_system_exception)
    orphaned_mask = (thread_counts == 0) & (ram_bytes > 0) & (~is_legitimate_system_exception)
    
    hog_pids      = pids[resource_hog_mask]
    orphaned_pids = pids[orphaned_mask]
    
    total_scanned_processes = os_matrix.shape[0]
    total_anomalies = np.sum(resource_hog_mask | orphaned_mask)
    system_compromise_ratio = (total_anomalies / total_scanned_processes) * 100
    
    return {
        "resource_exhaustion_suspects": hog_pids.astype(int).tolist(),
        "orphaned_stealth_suspects": orphaned_pids.astype(int).tolist(),
        "compromise_percentage": round(system_compromise_ratio, 2),
        "total_audited": total_scanned_processes
    }

def write_siem_alert_log(report: dict):
    """
    Enterprise Logger: Commits critical anomalies to timestamped 
    JSON files inside a dedicated security directory.
    """
    # Create a local logs directory if it doesn't exist yet
    log_dir = "./siem_logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # Generate an ISO 8601 compliant file safe timestamp string
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{log_dir}/incident_report_{timestamp}.json"
    
    # Inject metadata directly into the report dictionary
    report["timestamp"] = datetime.now().isoformat()
    report["classification"] = "CRITICAL_ALERT" if report["compromise_percentage"] > 0 else "SYSTEM_HEALTHY"
    
    # Write structural data to disk
    with open(filename, "w") as log_file:
        json.dump(report, log_file, indent=4)
        
    print(f"💾 Incident report committed to disk: {filename}")

if __name__ == "__main__":
    print(" [STAGE 1] Intercepting Live Operating System Process Table...")
    kernel_matrix = capture_and_normalize_kernel_state()
    print(f"✅ Telemetry Normalisation Complete. Total Records: {kernel_matrix.shape[0]}")
    
    print("\n🔍 [STAGE 2] Running Vector Security Analytics Over Raw Primitives...")
    start_time = time.perf_counter()    
    siem_report = audit_live_kernel_vectors(kernel_matrix)
    end_time = time.perf_counter()
    latency_ms = (end_time - start_time) * 1000
    print("\n" + "="*55)
    print("  KERNEL RISK TRIAGE METRICS  ")
    print("="*55)
    print(f"Total Live Audited Processes   : {siem_report['total_audited']}")
    print(f"Host System Compromise Ratio   : {siem_report['compromise_percentage']}%")
    print(f"Vector Engine Latency          : {latency_ms:.4f} ms")
    print("-"*55)
    print(f" Resource Exhaustion PIDs    : {siem_report['resource_exhaustion_suspects']}")
    print(f"Orphaned Stealth PIDs        : {siem_report['orphaned_stealth_suspects']}")
    #gives pid 76 which belongs to the registry process.It is a pure memory containerand hence has 0 threads
    print("[STAGE 3] Cheacking Security Triggers For Log Offloading")
    write_siem_alert_log(siem_report)