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
    and returns a structured 2D uint64 matrix for vector threat scanning.
    
    Matrix Structural Format:
    [ Process_ID, Resident_Set_Size_Bytes, Total_Threads, Active_File_Handles ]
    """
    max_expected=2048  #patch:pre allocate numpy block to prevent 0(N) fragmentation while list.append
    buffer=np.zeros((max_expected,4), dtype=np.uint64)
    #fix: evaluate os constext strictly outside loop to prevent branch penalties
    target_os=sys.platform
    is_win = (target_os == 'win32')
    attrs = ['pid', 'memory_info', 'num_threads', 'num_handles' if is_win else 'open_files']

    idx=0    
    # Querying the active kernel thread table 
    for process in psutil.process_iter(attrs):
        if idx >= max_expected:
            print("[WARNING] Process count exceeded pre-allocated buffer bounds.")
            break   #safety bounds for extreme edge case overflow

        try:
            # Extractimg basic kernel attributes
            pid = int(process.info.get('pid', 0))
            
            # Memory RSS (Resident Set Size): The physical RAM allocated to this process
            mem_info = process.info.get('memory_info')
            rss = int(mem_info.rss) if mem_info is not None else 0
            
            threads = int(process.info.get('num_threads') or 0)
            
            try:
                raw_handles = process.info.get('num_handles' if is_win else 'open_files')
                
                if is_win:
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
                
            buffer[idx, 0] = pid
            buffer[idx, 1] = rss
            buffer[idx, 2] = threads
            buffer[idx, 3] = open_handles
            idx += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return buffer[:idx]


def audit_live_kernel_vectors(os_matrix: np.ndarray, whitelist_pids: np.ndarray) -> dict:
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
    # patch: replace hardcoded pids with dynamic whitelist mask 
    is_threat =np.ones(os_matrix.shape[0], dtype=bool)
    for wp in whitelist_pids:
        is_threat &= (pids != wp)
    # Apply in placebitwise masks to prevent intermediate array creation 
    resource_hog_mask = (handle_counts > 3000)
    resource_hog_mask &= (ram_bytes < FIFTY_MB)
    resource_hog_mask &= is_threat
    orphaned_mask = (thread_counts == 0)
    orphaned_mask &= (ram_bytes > 0)
    orphaned_mask &= is_threat
    
    hog_pids      = pids[resource_hog_mask]
    orphaned_pids = pids[orphaned_mask]
    
    total_scanned_processes = os_matrix.shape[0]
    total_anomalies = np.sum(resource_hog_mask | orphaned_mask)
    system_compromise_ratio = 0
    if total_scanned_processes > 0:
        system_compromise_ratio= (total_anomalies / total_scanned_processes) * 100   
    return {
        "resource_exhaustion_suspects": hog_pids,
        "orphaned_stealth_suspects": orphaned_pids,
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
    filename = os.path.join(log_dir, f"incident_report_{timestamp}.json")  #replace hardcoded forward slash with os agnostic path join

    export_payload = {
        "resource_exhaustion_suspects": report["resource_exhaustion_suspects"].astype(int).tolist(),
        "orphaned_stealth_suspects": report["orphaned_stealth_suspects"].astype(int).tolist(),
        "compromise_percentage": report["compromise_percentage"],
        "total_audited": report["total_audited"],
        "timestamp": datetime.now().isoformat(),
        "classification": "CRITICAL_ALERT" if report["compromise_percentage"] > 0 else "SYSTEM_HEALTHY"
    }
    
    # Write structural data to disk
    with open(filename, "w") as log_file:
        json.dump(export_payload, log_file, indent=4)
        
    print(f"💾 Incident report committed to disk: {filename}")

if __name__ == "__main__":
    print(" [STAGE 1] Intercepting Live Operating System Process Table...")
    kernel_matrix = capture_and_normalize_kernel_state()
    print(f"✅ Telemetry Normalisation Complete. Total Records: {kernel_matrix.shape[0]}")
    if sys.platform == 'win32':
        dynamic_whitelist = np.array([0, 4, 76], dtype=np.uint64)  #os-agnostic dynamic whitelisting
    else:
        dynamic_whitelist = np.array([0, 1, 2], dtype=np.uint64)
    print("\n🔍 [STAGE 2] Running Vector Security Analytics Over Raw Primitives...")
    _ = audit_live_kernel_vectors(kernel_matrix[:5] , dynamic_whitelist)
    start_time = time.perf_counter()    
    siem_report = audit_live_kernel_vectors(kernel_matrix , dynamic_whitelist)
    end_time = time.perf_counter()
    latency_ms = (end_time - start_time) * 1000
    print("\n" + "="*55)
    print("  KERNEL RISK TRIAGE METRICS  ")
    print("="*55)
    print(f"Total Live Audited Processes   : {siem_report['total_audited']}")
    print(f"Host System Compromise Ratio   : {siem_report['compromise_percentage']}%")
    print(f"Vector Engine Latency          : {latency_ms:.4f} ms")
    print("-"*55)
    print(f" Resource Exhaustion PIDs    : {siem_report['resource_exhaustion_suspects'].tolist()}")
    print(f"Orphaned Stealth PIDs        : {siem_report['orphaned_stealth_suspects'].tolist()}")
    #gives pid 76 which belongs to the registry process.It is a pure memory containerand hence has 0 threads
    print("[STAGE 3] Checking Security Triggers For Log Offloading")
    write_siem_alert_log(siem_report)