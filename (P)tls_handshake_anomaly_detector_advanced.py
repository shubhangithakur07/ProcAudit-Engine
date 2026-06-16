'''PROBLEM STATEMENT: 
    High-Throughput TLS Handshake Anomaly & Exfiltration Detection Engine [ADVANCED TRIAGE EDITION].
    
    This advanced variant builds directly upon the foundational matrix parsing architecture
    by introducing Dynamic Threat Severity Scoring and Vectorized Incident Triage. 
    Instead of simple true/false filtering, connections are assigned mathematical 
    penalties across a 100-point threshold scale, then natively sorted via parallel 
    indices to bubble the most critical operational threats directly to the top.

INPUT FORMAT & CONSTRAINTS:
    Identical to the baseline tracking engine. O(1) attribute extraction, 
    strictly zero iteration loops allowed. Sorting implemented via O(N log N) C-native execution.'''

import numpy as np

def tls_audit_advanced(net_strm: np.ndarray) -> dict:
    con_ids = net_strm[:, 0]   
    ci_counts = net_strm[:, 1] 
    byts = net_strm[:, 2]      
    bytr = net_strm[:, 3]      
    certval = net_strm[:, 4]   

    exfratio = byts / (bytr + 0.000001)

    #DYNAMIN RISK VECTORIZATION BEGINS
    cipenalty=np.where(ci_counts<8.0,40.0,0.0)
    certpenalty=np.where(certval<7.0,20.0,0.0)

    raw_exfilpenalty=exfratio*5
    exfilpenalty=np.where(raw_exfilpenalty>40.0,40.0,raw_exfilpenalty)
    exfilpenalty=np.where(byts>1000.0,exfilpenalty,0.0)  #filtering out tiny background data

    #defining masks
    totalpenalty=cipenalty+certpenalty+exfilpenalty
    critical=totalpenalty>50.0
    criticalids=con_ids[critical]
    criticalscores=totalpenalty[critical]
    #sorting begins
    sortedin=np.argsort(-criticalscores)
    sortedids=criticalids[sortedin]
    sortedscores=criticalscores[sortedin]

    #summary of audit
    total_cons = net_strm.shape[0]
    mal= totalpenalty > 0.0   #Anything that can pose as a threat is malicious so safe ids would only be ones with total penalty=0
    overallthreat=(np.sum(mal) / total_cons)*100

    prioritisedincidents=np.column_stack((sortedids,sortedscores))
    return {
        "prioritised_incidents": prioritisedincidents.tolist(),
        "threat_percentage": round(overallthreat, 2)
    }



#TIME TO CHECK
if __name__ == "__main__":
    np.random.seed(42)
    total_records = 10000
    
    conn_ids = np.arange(1000, 1000 + total_records)
    ciphers  = np.random.randint(15, 30, size=total_records)
    b_sent   = np.random.randint(500, 5000, size=total_records)
    b_recv   = np.random.randint(2000, 20000, size=total_records)
    v_days   = np.random.randint(90, 365, size=total_records)
    
    # Inject Malicious Anomalies
    ciphers[150] = 5;   b_sent[150] = 85000;  b_recv[150] = 1200
    ciphers[920] = 4;   b_sent[920] = 120000; b_recv[920] = 800
    v_days[412] = 3
    v_days[7055] = 1
    
    simulated_traffic = np.column_stack((conn_ids, ciphers, b_sent, b_recv, v_days))
    forensic_report = tls_audit_advanced(simulated_traffic)

    print("---------------------------------------------------------")
    print("IIT ADVANCED METRIC SCORING AND TRIAGE SECURITY ENGINE")
    print("---------------------------------------------------------")
    print(f"Total network connections scanned:{total_records}")
    print(f"Sorted critical incidents: {forensic_report['prioritised_incidents']}")
    print(f"Overall threat percentage: {forensic_report["threat_percentage"]}")




