"""
IITK Portfolio Submission - BCyber Core Component
Author: Shubhangithakur07
Project: ProcAudit-Engine (Pipeline Guard Component)
Description: Lightweight integrity enforcement layer designed to detect 
             broken access control overrides and database tampering.
"""

import hashlib
import os
import json

def get_file_hash(path: str) -> str:
    """Calculates SHA-256 hash of a telemetry log file using 4KB block increments 
    to protect system memory from resource exhaustion attacks.
    """
    if not os.path.exists(path):
        return ""
    
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            #chunk-based data reading to stream telemetry blocks safely later
            while chunk := f.read(4096):
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
    print("     __IITK PORTFOLIO:CRYPTOGRAPHIC INTEGRITY MONITOR__        ")
    
    
    log_dir = "./siem_logs"
    if not os.path.exists(log_dir):
        print(" Target directory missing. Please boot the core engine telemetry layer first.")
        return

    # Ingesting the latest runtime JSON telemetry block from active logs
    try:
        log_files = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.json')]
    except Exception as e:
        print(f" Critical: Failed to scan directory {log_dir}. Reason: {e}")
        return
    
    if not log_files:
        print("Error: No telemetry datasets detected for verification signing.")
        return
        
    active_log = max(log_files, key=os.path.getctime)
    print(f" Ingesting active pipeline log: {active_log}")
    
   # Incident is over. Need to generate the pristine baseline hash now.
    baseline_signature = get_file_hash(active_log)
    if not baseline_signature:
        print("[-] Aborting: Could not generate baseline hash due to file read failure.")
        return
        
    print(f" Pristine Baseline Hash Generated:\n    -> {baseline_signature}\n")
    
    # simulation phase: Testing Broken Access Control / Tamper Vectors ---
    print(" Running simulation: Attempting unauthorized parameter manipulation...")
    
    try:
        with open(active_log, "r") as f:
            live_data = json.load(f)
            
       # Metrics mismatch issue shown because attack payload mutation skews tracking metrics.
       # (Simulating backend bug: client inputs are directly updating database states.)

        tampered_payload = live_data.copy()
        tampered_payload["compromise_percentage"] = 99.9  
        
        temp_simulation_file = active_log.replace(".json", "_TAMPER_TEST_TMP.json")
        with open(temp_simulation_file, "w") as f:
            json.dump(tampered_payload, f)
            
    except json.JSONDecodeError:
        print(" Simulation Failed: Target log file is corrupted or not valid JSON.")
        return
    except IOError as e:
        print(f" Disk I/O Error during attack simulation: {e}")
        return
        
    # Recalculating the signature since the telemetry block is mutated now.
    tampered_signature = get_file_hash(temp_simulation_file)
    print(f" Mutated File Cryptographic Signature:\n    -> {tampered_signature}\n")
    
    # Evaluation checks against baseline
    if baseline_signature == tampered_signature:
        print("[SUCCESS!] Operational state uncompromised. Logs verified clean.")
    else:
        print("[CRITICAL ALERT!] TELEMETRY INTEGRITY BREACH DETECTED!")
        print("     Mismatch flagged: Unsanitized writes located in system log array.")
    
    # get rid of runtime simulation scraps properly to avoid overhead
    if os.path.exists(temp_simulation_file):
        try:
            os.remove(temp_simulation_file)
        except OSError:
            print(f"[!] Warning: Could not auto-cleanup temporary asset: {temp_simulation_file}")
            
    print("\n------------------------------------------------------------------")

if __name__ == "__main__":
    verify_system_integrity()
