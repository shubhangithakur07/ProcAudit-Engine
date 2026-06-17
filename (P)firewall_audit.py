"""
PROBLEM STATEMENT 1: High-Throughput Firewall Log Audit Engine
SCENARIO: Enterprise gateway generating millions of log lines. 
          Vectorized matrix processing used to avoid loop latency.
"""
import numpy as np


#[ Packet_ID, Source_IP_Hash, Destination_Port, Packet_Size_Bytes ]
np.random.seed(42)
packet_ids = np.arange(1000, 2000)
ip_hashes = np.random.randint(10000, 99999, size=1000)
ports = np.random.choice([80, 443, 22, 21, 9999], size=1000, p=[0.4, 0.4, 0.1, 0.05, 0.05])
packet_sizes = np.random.randint(40, 1500, size=1000)

# Inject anomalies (negative sizes and rogue port traffic)
packet_sizes[15] = -500
packet_sizes[120] = -12

raw_logs = np.column_stack((packet_ids, ip_hashes, ports, packet_sizes))


#  Vertical Slicing
ports_col = raw_logs[:, 2]
sizes_col = raw_logs[:, 3]

# Boolean Masking (The Filters)
corrupted_mask = sizes_col < 0
rogue_port_mask = ports_col == 9999

# Combine filters using bitwise OR (|)
malicious_mask = corrupted_mask | rogue_port_mask

# Extract the flagged Packet IDs using Boolean Indexing
flagged_packet_ids = raw_logs[malicious_mask, 0]

print("--- FIREWALL AUDIT COMPLETE ---")
print(f"Total Malicious Packets Found: {len(flagged_packet_ids)}")
print(f"Flagged IDs: {flagged_packet_ids.tolist()[:5]}... (truncated)")