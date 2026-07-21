"""
Enterprise Pipeline Guard Component
Lightweight integrity enforcement layer designed to detect 
broken access control overrides and database tampering.
Developer: shubhangithakur07
"""

import hashlib
import os
import json
import time

cache_chunk_size=65536
def get_file_hash(path: str) -> str:
    """Calculates SHA-256 hash of a telemetry log file using O(1) memory streams"""
    if not os.path.exists(path):
        return ""
    
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            #chunk-based data reading to stream telemetry blocks safely later
            while chunk := f.read(cache_chunk_size):#changed from 4kb to 64kb, perfectly alings with L1/L2 cache
                sha.update(chunk)
    except (PermissionError, FileNotFoundError) as e:
        print(f"[-] Access Error during hashing routine: {e}")
        return ""
    except Exception as e:
        print(f"[-] Unexpected OS read error on {path}: {e}")
        return ""
            
    return sha.hexdigest()

def verify_system_integrity():
    print(" Initialising cryptographic integrity validation routine...")
    print("     __CRYPTOGRAPHIC INTEGRITY MONITOR__        ")
    
    
    log_dir = "./siem_logs"
    if not os.path.exists(log_dir):
        print(" Target directory missing. Please boot the core engine telemetry layer first.")
        return
    
    print(f" Scanning directory for active telemetry streams: {log_dir}")
    json_files = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.json')]

    if not json_files:
        print("[!] Error: No telemetry datasets detected for verification. Awaiting data...")
        return
    
    active_log = max(json_files, key=os.path.getctime)
    print(f" [+] Locked onto active pipeline log: {active_log}")

   # Incident is over. Need to generate the pristine baseline hash now.
    baseline_signature = get_file_hash(active_log)
    if not baseline_signature:
        print("[-] Aborting: Could not generate baseline hash due to file read failure.")
        return
        
    print(f" Pristine Baseline Hash Generated:\n    -> {baseline_signature}\n")
    
    # ACTIVE MONITORING PHASE: Testing Broken Access Control / Tamper Vectors ---
    #------------------------------------------------------------------------------
    print(" [*] Entering continuous polling state (Monitoring for out-of-band tampering)...")
    print("     (To test: open the JSON file and manually change a value, then save)")
    
    try:
        #implementing a daemon run limit of 30 seconds (6cycles 5 second each) for pipeline testing purpose
        for i in range(6): 
            time.sleep(5) 
            current_sign = get_file_hash(active_log)

            if not current_sign:
                print(" [CRITICAL] Target log file became unreadable or was deleted!")
                break

            if baseline_signature != current_sign:
                print("\n [CRITICAL ALERT] TELEMETRY INTEGRITY BREACH DETECTED!")
                print(f"     -> Baseline : {baseline_signature}")
                print(f"     -> Mutated  : {current_sign}")
                print("     -> Mismatch flagged: Unsanitized writes located in system log array.")
                return 
            print(f"     [+] Cycle {i+1}/6: Log integrity verified clean.")

    except KeyboardInterrupt:
        print("\n [*] Daemon halted by system administrator.")

    print("\n------------------------------------------------------------------")

if __name__ == "__main__":
    verify_system_integrity()        
            
            
       