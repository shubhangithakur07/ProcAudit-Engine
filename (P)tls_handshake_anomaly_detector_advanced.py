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
import time

def tls_audit_advanced(net_strm: np.ndarray) -> dict:

    total_cons= net_strm.shape[0]
    if total_cons==0:
        return{
            "prioritised_incidents": np.empty(0, dtype=[('con-id', np.uint64), ('risk_score', np.uint64)]),
            "threat_percentage": 0.0
        }

    con_ids = net_strm[:, 0]   
    ci_counts = net_strm[:, 1] 
    byts = net_strm[:, 2]      
    bytr = net_strm[:, 3]      
    certval = net_strm[:, 4]

    #single workspace array allocation
    totalpenalty=np.zeros(total_cons, dtype=np.uint64)
    np.add(totalpenalty, 40, out=totalpenalty, where=(ci_counts < 8))
    np.add(totalpenalty, 20, out=totalpenalty, where=(certval < 7))

    exfratio = np.zeros(total_cons, dtype=np.uint64)#preallocate zero so that calculation happens only when byts !=0
    np.floor_divide(byts*100,bytr,out=exfratio,where=(bytr != 0))
    
    raw_exfilpenalty=(exfratio*5)//100
    np.minimum(raw_exfilpenalty, 40, out=raw_exfilpenalty)
    np.add(totalpenalty,raw_exfilpenalty,out=totalpenalty,where=(byts>1000))  #filtering out tiny background noise

    critical=totalpenalty>50
    criticalids=con_ids[critical]
    criticalscores=totalpenalty[critical]
    
    #sorting begins
    sortedin=np.argsort(criticalscores, kind='stable')[::-1] #avoid negation

    dtype_struct=[('con-id',np.uint64),('risk_score', np.uint64)]
    prioritisedincidents=np.empty(sortedin.size,dtype=dtype_struct)
    if sortedin.size:
       prioritisedincidents['con-id']=criticalids[sortedin]
       prioritisedincidents['risk_score']=criticalscores[sortedin]

    #summary of audit
    mal= np.count_nonzero(totalpenalty>0)  #Anything that can pose as a threat is malicious so safe ids would only be ones with total penalty=0
    overallthreat=(mal / total_cons)*100

    return {
        "prioritised_incidents": prioritisedincidents,
        "threat_percentage": round(overallthreat, 2)
    }



#TIME TO TEST
if __name__ == "__main__":
    np.random.seed(42)
    total_records = 10000
    
    conn_ids = np.arange(1000, 1000 + total_records, dtype=np.uint64)
    ciphers  = np.random.randint(15, 30, size=total_records, dtype=np.uint64)
    b_sent   = np.random.randint(500, 5000, size=total_records, dtype=np.uint64)
    b_recv   = np.random.randint(2000, 20000, size=total_records, dtype=np.uint64)
    v_days   = np.random.randint(90, 365, size=total_records, dtype=np.uint64)
    
    # inject malicious anomalies
    ciphers[150] = 5;   b_sent[150] = 85000;  b_recv[150] = 1200
    ciphers[920] = 4;   b_sent[920] = 120000; b_recv[920] = 800
    v_days[412] = 3;     b_sent[412] = 120000; b_recv[412] = 800
    v_days[7055] = 1
    
    simulated_traffic = np.column_stack((conn_ids, ciphers, b_sent, b_recv, v_days))
    start= time.perf_counter()
    forensic_report = tls_audit_advanced(simulated_traffic)
    end=time.perf_counter()
    latency=(end-start)*1000


    print("---------------------------------------------------------")
    print(" ADVANCED METRIC SCORING AND TRIAGE SECURITY ENGINE")
    print("---------------------------------------------------------")
    print(f"Total network connections scanned:{total_records}")
    print(f"Overall threat percentage: {forensic_report['threat_percentage']}")
    print(f"Vector engine latency: {latency:.4f} ms")
    print("\n \n Prioristised Crtical Incidents")
    for incident in forensic_report['prioritised_incidents']:
        con_id = int(incident['con-id'])
        score = int(incident['risk_score'])
        print(f"   -> Connection ID: {con_id} | Risk Score: {score}")




