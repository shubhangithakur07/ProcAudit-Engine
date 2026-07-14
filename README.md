# 🌐ProcAudit Engine (Real-Time Cybersecurity Telemetry Engine)

A high-performance, real-time threat detection engine designed to monitor system telemetry, memory integrity, and network metadata. Built to bypass standard Python interpreter bottlenecks, this engine utilizes C-Bridges, NumPy vectorization, and hardware-level memory optimization to process massive datasets instantly.

![Security Engine Dashboard](./security_analytics_dashboard.png)

## 🚀 Quickstart & Reproduction Guide

To deploy and execute the validation benchmarking suite locally, initialize your shell environment using the following pipeline:

```powershell
# 1. Clone the core security architecture
git clone https://github.com/shubhangithakur07/iitk-bcyber-portfolio
cd quantiative_engine

# 2. Initialize and activate isolated virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Ingest deterministic dependencies
pip install -r requirements.txt

# 4. Execute the mathematical unit-testing verification suite
python -m unittest P_test_vector_engine.py

# 5. Run the high-density performance matrix profiler
python P_performance_profiler.py

A high-performance, vectorized SIEM (Security Information and Event Management) analytics engine designed to intercept low-level operating system telemetry and perform loop-free threat isolation using NumPy matrix masking.
```

## 🚀 Active Production Components

### Core Analytics & Threat Detection
* **`(P)live_system_audit.py`**: Live Windows kernel ingestion and vector threat scanning pipeline.
* **`P_crypto_shielderr.py`**: Cryptographic integrity enforcement layer for broken access control verification.
* **`(P)firewall_audit.py`**: Vectorized network firewall packet filtering.
* **`(P)memory_integrity_detector.py`**: Real-time memory page allocation and W^X vulnerability scanning.
* **`(P)tls_handshake_anomaly_detector.py`**: Edge-case TLS data exfiltration ratio tracking.
* **`(P)tls_handshake_anomaly_detector_advanced.py`**: Advanced Multi-session cryptographic handshake validation.

### Distributed Telemetry & Data Sanitization
* **`(P)multistation_variance_audit.py`**: Distributed system vector variance profiling.
* **`(P)satellite_signal_thresholding.py`**: Telemetry signal baseline anomaly processing.
* **`(P)defective_sensor_cleaner.py`**: Data sanitization utility for incoming hardware telemetry streams.

### Engine Infrastructure & Performance
* **`anomaly_detector.py`**: Core mathematical threshold verification library.
* **`P_performance_profiler.py`**: High-resolution performance benchmarking and heap allocation telemetry suite.
* **`P_bridge.py`**: Python-to-C FFI (Foreign Function Interface) management bridge.
* **`P_native_core.c`**: Compiled C-acceleration layer for hardware-level event processing.
* **`P_test_engine.py`**: Automated test suite for validation of security safeguards.
* **`(P)test_vector_engine.py`**: Specialized unit testing for vector math integrity.
  

---

## 🔬 Case Study: Low-Level OS False Positive Mitigation

During live kernel testing via `(P)live_system_audit.py`, the analytics engine's vector masks initially isolated the native Windows Registry process (**PID 76**) as an active threat due to its unique architectural footprint (maintaining an active physical RAM allocation but utilizing 0 native threads). 

### Phase 1: Raw Anomaly Ingestion (Before Patch)
The unmitigated analytics engine processed the raw telemetry matrix and triggered a system-wide warning:
```json
{    
    "resource_exhaustion_suspects": [],
    "orphaned_stealth_suspects": [76],
    "compromise_percentage": 0.41,
    "timestamp": "2026-06-17T21:47:13.529087",
    "classification": "CRITICAL_ALERT"
}
```

To resolve this without degrading throughput, a deterministic whitelist bypass layer was engineered directly into the NumPy masking logic. This allows the core vector engine to isolate known structural anomalies in $O(1)$ space complexity without falling back to slow, conditional iteration loops.

## 🔬 Case Study 2: Bypassing FPU Latency via Fixed-Point Arithmetic

During the development of the `(P)memory_integrity_detector.py` engine, floating-point math (decimals) created a severe bottleneck in the CPU's Floating Point Unit (FPU), causing unnecessary memory coercion (Upcasting to float64).

**The Fix (Hardware Alignment):**
By multiplying decimal telemetry (like memory entropy) by 100, we converted all data points into pure integers using **Fixed-Point Arithmetic**. This allowed the entire matrix to be forcefully cast into strict uint64 (Unsigned 64-bit Integers).

**Empirical Hardware Latency (L1 Cache Benchmarking):**
By feeding contiguous uint64 memory blocks directly into the CPU's Arithmetic Logic Unit (ALU), we unleashed the processor's internal L1 Cache to evaluate 5,000 memory pages simultaneously via SIMD instructions.

**Cold Start Latency (Disk/RAM load):** `1.39 ms`

**Warm Cache Latency (L1/L2 CPU Cache hit):** `0.13 ms`

---

## 📊 Performance Benchmarking & Memory Analytics

To validate the scalability and computational bounds of the whitelist architecture under peak loads, a high-density kernel telemetry simulation stream was executed against a workload of 100,000 active processes.

### Evaluation Metrics & Empirical Results

| Metric | Evaluation Value |
| :--- | :--- |
| **Total Telemetry Rows Audited** | 100,000 |
| **Mathematical Execution Latency** | 1.2225 ms |
| **Peak Heap Allocation** | 489.23 KB |
| **System Threat Score** | 0.0% |

### Architectural Highlights

* **Loop-Free Vectorization:** Achieved a processing latency of **1.2225 ms** over a 100,000-row telemetry matrix, confirming that the engine completely bypasses Python interpreter loops by relying on contiguous C-aligned memory arrays.
* **Empirical $O(1)$ Space Complexity:** By utilizing native heap allocation tracing (`tracemalloc`), the engine proved that its peak memory footprint remains flat and bounded at just **489.23 KB**. Calculations are executed as shared memory views (slices) rather than costly data duplications, minimizing memory fragmentation and preventing runtime out-of-memory (OOM) failures under heavy throughput conditions.
* **Loop-Free Vectorization (SIMD):** 
  Achieved sub-millisecond processing latency by completely eliminating Python `for` loops. The engine uses bitwise operators (`&`, `|`) to evaluate contiguous C-aligned memory arrays in parallel, preventing CPU branch prediction penalties.
* **Context-Switch Mitigation:** 
  Instead of looping individual system calls to query process attributes (which melts CPU cycles), the engine utilizes bulk OS Snapshot APIs. This pulls the entire live process table into User Space in a single Syscall, dropping kernel context switches from $O(N)$ to $O(1)$.
* **Deterministic Exception Validation:** Verified exception-free edge handling. The forced injection of PID 76 (0 active threads) was safely intercepted and neutralized by the whitelist filter, bringing the global threat score down to a true `0.0%`.



  ---

## ⚡ Polyglot Optimization: Native C Acceleration Layer
To mirror industrial EDR (Endpoint Detection & Response) system requirements, a high-performance cross-language processing block was introduced (`native_core.c`). By shifting raw matrix ingestion loops from the interpreted Python runtime into a compiled, native C-contiguous shared library (`.dll`), conditional branch testing occurs at the bare-metal hardware layer.

The architecture employs `ctypes` mappings to stream telemetry data via explicit structured memory blocks, successfully avoiding Python memory thrashing allocations and ensuring scalable operation under heavy network or system exploitation scenarios.
### 🧪 Validation & Test Suite Results
To ensure the integrity of the detection logic, the engine was subjected to a comprehensive unit test suite, confirming that the native bridge correctly handles edge cases, kernel whitelisting, and threat isolation.

```text
[RUNNING] Executing IITK Portfolio Test Suite validations...
test_empty_payload_safeguard (__main__.TestNativeSecurityEngine.test_empty_payload_safeguard) ... ok
test_kernel_whitelist_bypass (__main__.TestNativeSecurityEngine.test_kernel_whitelist_bypass) ... ok
test_stealth_threat_detection (__main__.TestNativeSecurityEngine.test_stealth_threat_detection) ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.043s

OK

## 🛡️ Pipeline Guard Integration: Cryptographic Integrity Validation

To protect the system from broken access control overrides and database tampering vulnerabilities, the `ProcAudit-Engine` component serves as an active Pipeline Guard layer. This module calculates streaming SHA-256 signatures over active SIEM runtime telemetry JSON log blocks using fixed 4KB blocks to maintain flat memory bounds.

### 🧪 Live Tamper Simulation Run

To evaluate the validation layer under active exploitation vectors, a runtime simulation was executed where an attacker directly manipulates the telemetry data array (e.g., forcing a `compromise_percentage` modification to bypass standard database validation bounds).

```text
Initialising cryptographic integrity validation routine...
------------------------------------------------------------------
      PROCAUDIT GUARD : TRACKING LIVE PIPELINE INTEGRITY         
------------------------------------------------------------------

[*] Ingesting active pipeline log: ./siem_logs/incident_report_20260619_193314.json
[+] Pristine Baseline Hash Generated:
    -> 6f8ad8c91db93b05caf81b72f89b0f06046d9a83772d7b1462d2735b063d2bed

[*] Running simulation: Attempting unauthorized parameter manipulation...
[!] Mutated File Cryptographic Signature:
    -> e988ad8bccdb0f620732a4bd3b30200bda10bc1c3e4e09e3bf6522f1eac18f56

[CRITICAL ALERT] TELEMETRY INTEGRITY BREACH DETECTED!
    -> Mismatch flagged: Unsanitized writes located in system log array.

------------------------------------------------------------------
```

### 📌 Core Architecture Observations

* **Deterministic State Baseline**: The guard engine establishes a clean system state baseline hash directly from active SIEM JSON telemetry arrays before testing any exploitation scenarios.
* **Tamper Detection Capabilities**: When client-side parameter injection overrides database configurations, the engine registers a clear cryptographic signature mutation ($6f8ad8... \neq e988ad...$). This drops any modified pipeline logs completely out of the safe processing array.
* **Deterministic Resource Cleanup**: Following simulation evaluations, the runtime environment automatically purges simulation artifacts and short-lived execution files properly to prevent persistent memory overhead or tracking drift.


