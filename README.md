# Quantitative Security Analytics Engine

A high-performance, vectorized SIEM (Security Information and Event Management) analytics engine designed to intercept low-level operating system telemetry and perform loop-free threat isolation using NumPy matrix masking.

## 🚀 Active Production Components
* **`(P)live_system_audit.py`**: Live Windows kernel ingestion and vector threat scanning pipeline.
* **`(P)firewall_audit.py`**: Vectorized network firewall packet filtering.
* **`(P)memory_integrity_detector.py`**: Real-time memory page allocation and W^X vulnerability scanning.
* **`(P)tls_handshake_anomaly_detector.py`**: Edge-case TLS data exfiltration ratio tracking.
* **`(P)tls_handshake_anomaly_detector_advanced.py`**: Advanced Multi-session cryptographic handshake validation.
* **`(P)multistation_variance_audit.py`**: Distributed system vector variance profiling.
* **`(P)satellite_signal_thresholding.py`**: Telemetry signal baseline anomaly processing.
* **`(P)defective_sensor_cleaner.py`**: Data sanitization utility for incoming hardware telemetry streams.
* **`anomaly_detector.py`**: Core mathematical threshold verification library.

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