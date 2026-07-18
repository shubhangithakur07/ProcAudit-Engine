# 🌐ProcAudit Engine (Real-Time Cybersecurity Telemetry Engine)

A high-performance, real-time threat detection engine designed to monitor system telemetry, memory integrity, and network metadata.Built to bypass standard interpreted language bottlenecks, this engine utilizes C-Bridges, NumPy SIMD vectorization, and cache-aligned memory optimization to evaluate massive process and network datasets with sub-millisecond latency.

![Security Engine Dashboard](./enterprise_security_dashboard.png)


## 🎯 Architectural Philosophy 
Standard security scripts often rely on sequential iteration (`for`/`while` loops) and dynamic typing, which introduce severe interpreter overhead and CPU branch prediction penalties.

This engine was built under strict engineering constraints to achieve empirical $O(1)$ space complexity and minimize execution latency:

1.**Branchless Logic:** Elimination of standard loops in favor of bitwise Boolean masking.

2.**Hardware Alignment:** Strict upcasting to `uint64_t` to bypass Floating Point Unit (FPU) latency.

3.**Contiguous Memory:** Leveraging C-arrays to ensure data fits cleanly within CPU L1/L2 cache lines.

## 🚀 Quickstart & Reproduction Guide

To deploy and execute the validation benchmarking suite locally, initialize your shell environment using the following pipeline:

```powershell
# 1. Clone the core security architecture
git clone https://github.com/shubhangithakur07/ProcAudit-Engine.git
cd quantiative_engine

# 2. Initialize and activate isolated virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Ingest deterministic dependencies
pip install -r requirements.txt

# 4. Execute the mathematical unit-testing verification suite
python -m unittest P_test_engine.py
python -m unittest P_test_vector_engine.py

# 5. Run the high-density performance matrix profiler
python P_performance_profiler.py

#6. Generate the visual analytics dashboard
python P_analytics_visualizer.py

```


## 🚀 Active Production Components

### Core Analytics & Threat Detection
* **`(P)live_system_audit.py`**: Live Windows kernel ingestion and vector threat scanning pipeline.
* **`P_crypto_shielderr.py`**: Cryptographic integrity enforcement layer for broken access control verification.
* **`(P)firewall_audit.py`**: Vectorized network firewall packet filtering.
* **`(P)memory_integrity_detector.py`**: Real-time memory page allocation and W^X vulnerability scanning.
* **`(P)tls_handshake_anomaly_detector.py`**: Edge-case TLS data exfiltration ratio tracking.
* **`(P)tls_handshake_anomaly_detector_advanced.py`**: Advanced Multi-session cryptographic handshake validation.

### Distributed Telemetry & Data Sanitization(Can be accessed from the research archive)
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

## 🏗️ The 5 Pillars of the Architecture

### 1. Data Acquisition (The OS Sensor)

• **File:** `(P)live_system_audit.py`

• **Mechanism:** Utilizes bulk OS Snapshot APIs via `psutil` to pull the entire live process table into User Space in a single System Call, dropping kernel context switches from $O(N)$ to $O(1)$.

• **Known Limitations:** Operates in Ring-3 (User Space). Acknowledged vulnerability to Ring-0 Rootkits that hook native OS APIs prior to ingestion.

### 2. Algorithmic Triage (The Vector Engine)

• **File:** `(P)memory_integrity_detector.py`

• **Mechanism:** Achieves processing latency of ~1.22 ms over a 100,000-row telemetry matrix. By utilizing native heap allocation tracing (`tracemalloc`), the engine proved that its peak memory footprint remains flat and bounded at just **489 KB**. Calculations are executed as shared memory views (boolean masks) rather than costly data duplications, preventing runtime Out-Of-Memory (OOM) failures under heavy throughput.

### 3. Network Analytics (Advanced TLS Triage)

• **File:** `tls_handshake_anomaly_detecter_advanced.py`

• **Mechanism:** Mathematical scoring of TLS Handshake metadata (JA3 mismatch indicators, exfiltration ratios) to detect Command & Control (C2) beaconing. Implements safe branchless division (`np.divide` with `out=zeros_like`) to prevent Divide-by-Zero CPU interrupts, and utilizes $O(N \log N)$ native `argsort` for dynamic threat prioritization.

### 4. Polyglot Optimization (The C-Bridge)

• **Files:** `P_bridge.py`, `P_native_core.c`

• **Mechanism:** To mirror industrial EDR (Endpoint Detection & Response) systems, raw matrix ingestion is shifted into a compiled, native C-contiguous shared library. The architecture employs `ctypes` to pack data into strict 32-byte structs (perfectly aligned for 64-byte CPU cache fetches), achieving bare-metal execution latencies of < **0.09 ms**.

### 5. Data Integrity (The Crypto Guard)

• **File:** `P_crypto_shielderr.py`

• **Mechanism:** Defends the SIEM JSON output logs against Broken Access Control and post-incident tampering. Ingests log files using $O(1)$ memory generator expressions () and calculates SHA-256 cryptographic signatures using **64KB chunk increments** to perfectly saturate modern CPU cache lines without exhausting system RAM.
  

---
## 📊 Performance Benchmarking & Memory Analytics

To validate the scalability and computational bounds of the whitelist architecture under peak loads, a high-density kernel telemetry simulation stream was executed against a workload of 100,000 active processes.

### Evaluation Metrics & Empirical Results

| Metric | Evaluation Value |
| :--- | :--- |
| **Total Telemetry Rows Audited** | 100,000 |
| **C-Engine Native Latency** |<0.09ms |
| **Mathematical Execution Latency** | 1.2225 ms |
| **Peak Heap Allocation** | 489.23 KB |
| **System Threat Score** | 0.0% (Post-whitelist)|



## 🔬 Case Study 1: Low-Level OS False Positive Mitigation

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

