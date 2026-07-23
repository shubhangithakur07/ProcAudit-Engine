# 🌐ProcAudit Engine (Real-Time Cybersecurity Telemetry Engine)

A high-performance, real-time threat detection engine designed to monitor system telemetry, memory integrity, and network metadata.Built to bypass standard interpreted language bottlenecks, this engine utilizes C-Bridges, NumPy SIMD vectorization,Memory-Mapped I/O (mmap) and cache-aligned memory optimization to evaluate massive process and network datasets with sub-millisecond latency.

![Security Engine Dashboard](./enterprise_security_dashboard.png)


## 🎯 Architectural Philosophy 
Standard security scripts often rely on sequential iteration (`for`/`while` loops) and dynamic typing, which introduce severe interpreter overhead and CPU branch prediction penalties.

This engine was built under strict engineering constraints to achieve empirical $O(1)$ space complexity and minimize execution latency:

1.**Branchless Logic:** Elimination of standard loops in favor of bitwise Boolean masking.

2.**Hardware Alignment:** Strict upcasting to `uint64_t` to bypass Floating Point Unit (FPU) latency.

3.**Contiguous Memory:** Leveraging C-arrays to ensure data fits cleanly within CPU L1/L2 cache lines.

4.**Zero-Copy Disk I/O:**Implementation of Memory-Mapped virtual memory bridges to read payload data directly from physical disks without OS kernel copying.

## 🚀 Quickstart & Reproduction Guide

To deploy and execute the validation benchmarking suite locally, initialize your shell environment using the following pipeline:

```powershell
# 1. Clone the core security architecture
git clone https://github.com/shubhangithakur07/ProcAudit-Engine.git
cd ProcAudit-Engine

# 2. Initialize and activate isolated virtual environment
python -m venv venv

# Activate (Windows PowerShell):
.\venv\Scripts\Activate.ps1
# Activate (Linux/macOS):
source venv/bin/activate

# 3. Ingest deterministic dependencies (psutil, numpy, matplotlib)
pip install -r requirements.txt

# 4. Execute the mathematical unit-testing verification suite
python P_test_engine.py
python "(P)test_vector_engine.py"

# 5. Execute the zero-copy ingestion benchmarks
python P_mmap_bridge.py

# 6. Run the high-density performance matrix profiler
python P_performance_profiler.py

# 7. Generate the visual analytics dashboard
python P_analytics_visualizer.py

```

## 🏗️ The 5 Pillars of the Architecture

### 1. Data Acquisition (The OS Sensor)

• **File:** `(P)live_system_audit.py`

• **Mechanism:** Utilizes bulk OS Snapshot APIs via `psutil` to pull the entire live process table into User Space in a single System Call, dropping kernel context switches from $O(N)$ to $O(1)$.

•**Performance:**Normalizes and scores live systems (e.g., 278 concurrent processes) with a warm cache latency of **~0.10 ms**.

• **Known Limitations:** Operates in Ring-3 (User Space). Acknowledged vulnerability to Ring-0 Rootkits that hook native OS APIs prior to ingestion.

### 2. Algorithmic Triage (The Vector Engine)

• **File:** `(P)memory_integrity_detector.py` , `

• **Mechanism:** Achieves processing latency of ~1.81 ms over a 100,000-row telemetry matrix. By utilizing native heap allocation tracing (`tracemalloc`), the engine proved that its peak memory footprint remains flat and bounded at just **456.51 KB**. Calculations are executed as shared memory views (boolean masks) rather than costly data duplications, preventing runtime Out-Of-Memory (OOM) failures under heavy throughput.

•**Performance:**Achieves sub-millisecond latency (averaging **~0.09 ms**) while sweeping a dense 5,000-page memory matrix to identify rogue code injection and hidden payloads.

### 3. Network Analytics (Advanced TLS Triage)

• **File:** `tls_handshake_anomaly_detector_advanced.py`

• **Mechanism:** Mathematical scoring of TLS Handshake metadata (JA3 mismatch indicators, exfiltration ratios) to detect Command & Control (C2) beaconing. Implements safe branchless division (`np.divide` with `out=zeros_like`) to prevent Divide-by-Zero CPU interrupts, and utilizes $O(N \log N)$ native `argsort` for dynamic threat prioritization.

### 4. Polyglot Optimization (The C-Bridge & Zero-Copy Architecture)

• **Files:** `P_bridge.py`, `P_native_core.c`, `P_mmap_bridge.py`

• **Mechanism:** o mirror industrial EDR (Endpoint Detection & Response) systems, raw matrix ingestion is shifted into a compiled, native C-contiguous shared library. Update: Implemented zero-copy memory pointers via numpy.ctypeslib and injected dynamic OS kernel whitelisting, entirely removing hard-coded PIDs to establish OS parity.Advanced iterations utilize mmap to map physical binaries directly to RAM.

**Performance:**Audits a high-density, 100,000-row telemetry matrix natively in C. Hardware latency routinely benchmarks at **~0.42 ms.**

**Empirical Hardware Execution Benchmarks (Zero-Copy mmap I/O):**
```
[*] Generating synthetic 10MB binary log (300,000 telemetry rows)...
[*] Target Log: massive_sensor_dump.bin | 9.16 MB | 300,000 Rows
 ⚡ ZERO-COPY DISK-TO-CPU EXECUTION METRICS ⚡ 
------------------------------------------------------------
Size of file processed   : 9.16 MB
Total Rows Audited       : 300,000
Disk-to-C Latency        : 3.3758 ms
Detected Threats         : 1
Critical PIDs         : [999] ...
```

### 5. Data Integrity (The Crypto Guard)

• **File:** `P_crypto_shielderr.py`

• **Mechanism:** Defends the SIEM JSON output logs against Broken Access Control and post-incident tampering. Ingests log files using $O(1)$ memory generator expressions `()` and calculates SHA-256 cryptographic signatures using **64KB chunk increments** to perfectly saturate modern CPU cache lines without exhausting system RAM.
  

---
## 📊 Performance Benchmarking & Memory Analytics

To validate the scalability and computational bounds of the whitelist architecture under peak loads, a high-density kernel telemetry simulation stream was executed against a workload of 100,000 active processes.

### Evaluation Metrics & Empirical Results

| Metric | Evaluation Value | Hardware Impact|
| :--- | :--- | :--- |
| **Total Telemetry Rows Audited** | 100,000 | High-density load simulation |
| **C-Engine Native Latency** |~0.42ms |Zero-copy bare-metal evaluation |
| **mmap Disk-to-CPU (300k Rows)** |  ~3.37ms| Zero-copy Kernel I/O bypass|
| **Peak Heap Allocation** | 456.51 KB |Empirical  $O(1)$ space complexity|
| **System Threat Score** | 0.0%| Zero-copy bare-metal evaluation|



## 🔬Deep-Dive Into Hurdles

### 🔬 Case Study 1: Bypassing FPU Latency via Fixed-Point Arithmetic

During the development of the `(P)memory_integrity_detector.py` engine, floating-point math (decimals) created a severe bottleneck in the CPU's Floating Point Unit (FPU), causing unnecessary memory coercion (Upcasting to float64).

**The Fix (Hardware Alignment):**
By multiplying decimal telemetry (like memory entropy) by 100, we converted all data points into pure integers using **Fixed-Point Arithmetic**. This allowed the entire matrix to be forcefully cast into strict uint64 (Unsigned 64-bit Integers).

**Empirical Hardware Latency (L1 Cache Benchmarking):**
By feeding contiguous uint64 memory blocks directly into the CPU's Arithmetic Logic Unit (ALU), we unleashed the processor's internal L1 Cache to evaluate 5,000 memory pages simultaneously via SIMD instructions.

**Cold Start Latency (Disk/RAM load):** `1.39 ms`

**Warm Cache Latency (L1/L2 CPU Cache hit):** `0.0830 ms`

### Case Study 2: Pipeline Cryptographic Tamper Defense
To protect the system from broken access control overrides and database tampering vulnerabilities, the `P_crypto_shielderr.py` component serves as an active Pipeline Guard layer. It calculates streaming SHA-256 signatures over active SIEM runtime telemetry JSON log blocks in a continuous loop.

**Live Simulation Results:** When client-side parameter injection overrides database configurations, the daemon instantly registers a clear cryptographic signature mutation **($55d24b...  \neq 7e1c5f...$)**. 

```
Initialising cryptographic integrity validation routine...
     __CRYPTOGRAPHIC INTEGRITY MONITOR__        
 Scanning directory for active telemetry streams: ./siem_logs
 [+] Locked onto active pipeline log: ./siem_logs\incident_report_20260721_111215.json
 Pristine Baseline Hash Generated:
    -> 55d24bd48a9e409c70936d07dfe0de117aee3025b3d47e1d8e578f60690385f2

 [*] Entering continuous polling state (Monitoring for out-of-band tampering)...
     (To test: open the JSON file and manually change a value, then save)
     [+] Cycle 1/6: Log integrity verified clean.
     [+] Cycle 2/6: Log integrity verified clean.
     [+] Cycle 3/6: Log integrity verified clean.
     [+] Cycle 4/6: Log integrity verified clean.

 [CRITICAL ALERT] TELEMETRY INTEGRITY BREACH DETECTED!
     -> Baseline : 55d24bd48a9e409c70936d07dfe0de117aee3025b3d47e1d8e578f60690385f2
     -> Mutated  : 7e1c5f73930819d0c9b9ba2cfcb1f47dabb5b94aa43c19c95cd2d01dfe973efd
     -> Mismatch flagged: Unsanitized writes located in system log array.
```
## 🧪 CI/CD Testing & Latency Constraints
To ensure the integrity of the detection logic, the engine relies on a strict `unittest` suite. Beyond standard assertions, the pipeline enforces a **Hard Hardware Latency Constraint**, intentionally failing builds if the C-Engine and Python orchestrator fail to process 10,000 records within a **5.0 ms** threshold.

```
[RUNNING] Executing Native C-Engine Test Suite validations...
test_c_engine_latency_constraint (__main__.TestNativeSecurityEngine.test_c_engine_latency_constraint) ... ok
test_empty_payload_safeguard (__main__.TestNativeSecurityEngine.test_empty_payload_safeguard) ... ok
test_kernel_whitelist_bypass (__main__.TestNativeSecurityEngine.test_kernel_whitelist_bypass) ... ok
test_stealth_threat_detection (__main__.TestNativeSecurityEngine.test_stealth_threat_detection) ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.004s

OK
```
---

