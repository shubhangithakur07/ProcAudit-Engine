import numpy as np
import time

def audit_memory_integrity(memory_matrix: np.ndarray) -> dict:
    pgid = memory_matrix[:, 0]       # tracking purpose
    is_signed = memory_matrix[:, 2]  # 1-signed 0-unsigned
    permission = memory_matrix[:, 3] # 1=read only, 2=read/write, 3=read/write/execute
    entropy = memory_matrix[:, 4]     # measuring data randomness 

    # Threat 1: Unsigned pages with Write/Execute permissions (Catches injected code)
    injected_mask = (is_signed == 0) & (permission == 3)
    
    # Threat 2: Unsigned pages with high entropy (Catches packed/encrypted malware)
    # FIXED-POINT MATH:We use 650 instead of 6.5 because we multiplied entropy by 100 to bypass using decimals so we can use blazing-fast uint64 hardware integers
    packed_mask = (is_signed == 0) & (entropy > 650)
    
    # Combine masks using bitwise OR
    malicious_mask = injected_mask | packed_mask

    injected_ids = pgid[injected_mask]
    packed_ids = pgid[packed_mask]

    # Calculate global host compromise metrics
    total_pages = memory_matrix.shape[0]
    overall_threat=0
    if total_pages >0 :
        overall_threat = (np.sum(malicious_mask) / total_pages) * 100

    return {
        "injected_pages": injected_ids.astype(int).tolist(),
        "hidden_packed_payloads": packed_ids.astype(int).tolist(),
        "threat_percent": round(overall_threat, 2),
        "total_pages_scanned": total_pages
    }

#TESTING
if __name__ == "__main__":

    # Generates 5000 random memory pages for simulation
    np.random.seed(7)
    total_pages = 5000
    
    page_ids = np.arange(50000, 50000 + total_pages)
    process_ids = np.random.randint(100, 999, size=total_pages)
    signatures = np.random.choice([0, 1], p=[0.1, 0.9], size=total_pages) # 90% signed baseline
    permissions = np.random.choice([1, 2, 3], p=[0.4, 0.5, 0.1], size=total_pages)
    
    entropy = np.random.uniform(2.0, 5.5, size=total_pages) * 100
    
    #  (4.2 -> 420, 7.8 -> 780)
    signatures[412] = 0; permissions[412] = 3; entropy[412] = 420 
    signatures[895] = 0; permissions[895] = 2; entropy[895] = 780
    
    # Bind arrays into a 2D matrix, forcefully casting to hardware-efficient uint64
    simulated_memory = np.column_stack((page_ids, process_ids, signatures, permissions, entropy)).astype(np.uint64)
    _ = audit_memory_integrity(simulated_memory[:10])
    #timer
    start_time = time.perf_counter()
    report = audit_memory_integrity(simulated_memory)
    end_time = time.perf_counter()
    latency_ms = (end_time - start_time) * 1000
    
    print("="*50)
    print("🛡️  KERNEL MEMORY INTEGRITY REPORT  🛡️")
    print("="*50)
    print(f"Total Pages Scanned  : {report['total_pages_scanned']}")
    print(f"Overall Threat Level : {report['threat_percent']}%")
    print(f"Engine Latency       : {latency_ms:.4f} ms")
    print("-" * 50)
    
    #Looking solely at the ids is confusing, organised by adding the number of threats before naming them
    injected_count = len(report['injected_pages'])
    packed_count = len(report['hidden_packed_payloads'])
    print(f"🚨 Rogue Injected Pages ({injected_count} found): {report['injected_pages']}")
    print(f"📦 Hidden Packed Payloads ({packed_count} found): {report['hidden_packed_payloads']}")


