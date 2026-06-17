



import numpy as np
def audit_memory_integrity(memory_matrix: np.ndarray) -> dict:
    pgid=memory_matrix[:,0]  #tracking purpose
    processid=memory_matrix[:,1]    #system id of parent aplication
    is_signed=memory_matrix[:,2]    #1-signed 0-unsigned
    permission=memory_matrix[:,3]    #1=read only,2=read/write,3=read/write/execut
    entrpy=memory_matrix[:,4]  # measuring data randomness from 0.0 to 8.0 clean<5.0 mal>6.5

    injected=(is_signed==0) & (permission==3)
    packed=(is_signed==0) &(entrpy>6.5)
    mal=injected|packed

    injectedids=pgid[injected]
    packedids=pgid[packed]

    totalpages=memory_matrix.shape[0]
    overall_threat=(np.sum(mal)/totalpages)*100

    return{
        "injected_pages":injectedids.tolist(),
        "hiddenpackedpayloads":packedids.tolist(),
        "threatprcnt":round(overall_threat,2)
    }


#TESTING...
if __name__ == "__main__":

    # Generates 5000 random memory pages for simulation
    np.random.seed(7)
    total_pages = 5000
    
    page_ids   = np.arange(50000, 50000 + total_pages)
    process_ids = np.random.randint(100, 999, size=total_pages)
    signatures  = np.random.choice([0, 1], p=[0.1, 0.9], size=total_pages) # 90% signed baseline
    permissions = np.random.choice([1, 2, 3], p=[0.4, 0.5, 0.1], size=total_pages)
    entropy     = np.random.uniform(2.0, 5.5, size=total_pages)
    
    # injecting anomalies at index 412 and 895
    signatures[412] = 0; permissions[412] = 3; entropy[412] = 4.2 
    signatures[895] = 0; permissions[895] = 2; entropy[895] = 7.8
    
    simulated_memory = np.column_stack((page_ids, process_ids, signatures, permissions, entropy))
    report=audit_memory_integrity(simulated_memory)

    print("\n" + "="*40)
    print("🛡️  KERNEL MEMORY INTEGRITY REPORT  🛡️")
    print("="*40)
    print(f"Overall Threat Level : {report['threatprcnt']}%")
    print(f"🚨 Rogue Injected Pages: {report['injected_pages']}")
    print(f"📦 Hidden Packed Payloads: {report['hiddenpackedpayloads']}")
    




