'''PROBLEM STATEMENT: 
    High-Throughput TLS Handshake Anomaly & Exfiltration Detection Engine.
    
    In modern network security, advanced persistent threats (APTs) often utilize
    encrypted TLS tunnels to exfiltrate sensitive data. Because payloads are 
    encrypted, perimeter defenses must rely on structural anomalies within the 
    unencrypted TLS Handshake phase (e.g., Client Hello, Cipher Suite negotiation, 
    and Certificate Exchange) to identify command-and-control (C2) channels.

    This engine must parse a high-volume stream of raw connection metadata tuples 
    and identify two critical security anomalies using optimized, loop-free mathematical 
    operations:
      1. JA3 Fingerprint Mismatch / Data Beaconing: Identifying connections with 
         non-standard cipher suite counts paired with unusually high ratios of 
         sent-to-received bytes (indicative of reverse-shell data exfiltration).
      2. Certificate Duration Anomalies: Detecting ephemeral, short-lived rogue 
         certificates often used in automated malware infrastructure.

INPUT FORMAT (Simulated Network Stream Matrix):
    A 2D array where each row represents a single TLS connection event:
    [ Connection_ID, Cipher_Suite_Count, Bytes_Sent, Bytes_Received, Cert_Validity_Days ]

CONSTRAINTS & PERFORMANCE GOALS:
    - Strictly NO 'for' or 'while' loops for algorithmic scanning.
    - Utilize vectorized matrix masking to achieve O(1) processing latency per record.
    - Isolate malicious IP/Connection profiles with zero reliance on external state.'''

import numpy as np
import time
 # we'll be creating an immortal engine using def block to make it reusable
def tls_audit(net_strm: np.ndarray)  -> dict:
    con_ids=net_strm[:,0] #connection ids
    ci_counts=net_strm[:,1] #cipher counts  
    byts=net_strm[:,2] #bytes sent
    bytr=net_strm[:,3] #bytes received
    certval=net_strm[:,4] # certificate validity
    #Using np.divide with 'where' safety to avoid the 0.000001 decimal hack
    # This keeps our math clean and avoids unnecessary floating point errors
    exfratio= np.divide(byts, bytr, out=np.zeros_like(byts, dtype=np.float64), where=bytr!=0) #if some id is downloading way more than they are uploading
    exfidentify=(ci_counts <8) & (exfratio > 7.0) & (byts>1000)
    flagged_exfids=con_ids[exfidentify]
    #sucessfully confirmed exfiltration
    
    ephidentify=certval<7
    flagged_ephids=con_ids[ephidentify] #check for ephermeral ids

    total_cons=net_strm.shape[0]
    mal_ids=exfidentify |ephidentify 
    overallthreat=(np.sum(mal_ids)/ total_cons)*100  #threat prcentage

    return {
        "exfiltration_alerts": flagged_exfids.tolist(),
        "ephemeral_cert_alerts": flagged_ephids.tolist(),
        "threat_percentage": round(overallthreat, 2)
    }


#TESTING IT OUT

if __name__ == "__main__":
    np.random.seed(42)
    total_records=10000

    conn_ids=np.arange(1000,1000+total_records) #np.arange(start,stop)
    ciphers  = np.random.randint(15, 30, size=total_records)  
    b_sent   = np.random.randint(500, 5000, size=total_records)
    b_recv   = np.random.randint(2000, 20000, size=total_records)
    v_days   = np.random.randint(90, 365, size=total_records)
    #INJECTING ANOMALIES
    ciphers[150] = 5;   b_sent[150] = 85000;  b_recv[150] = 1200
    ciphers[920] = 4;   b_sent[920] = 120000; b_recv[920] = 800
    v_days[412] = 3
    v_days[7055] = 1

    simulatedtrfc = np.column_stack((conn_ids, ciphers, b_sent, b_recv, v_days)).astype(np.uint64)
    start= time.perf_counter()
    forensic_report=tls_audit(simulatedtrfc)
    end=time.perf_counter()
    latency_ms=(end - start)*1000
    #FINAL OUTPUT
    print("-----------------------------------------------------")
    print("        TLS TRAFFIC ENGINE SECURITY AUDIT     ")
    print("-----------------------------------------------------")
    print(f"Tota networks scanned : {total_records}")
    print(f"Data exfiltration suspects flagged: {forensic_report['exfiltration_alerts']}")
    print(f"Ephermeral certificate tunnels flagged: {forensic_report['ephemeral_cert_alerts']}")
    print(f"Overall network threat density: {forensic_report['threat_percentage']}%")
    print(f"Vector Engine latency: {latency_ms:.4f} ms")








        
   