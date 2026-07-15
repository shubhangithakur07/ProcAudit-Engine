/* * SECURITY ENGINE CORE - TELEMETRY AUDIT
 * Author: Shubhangithakur07
 * Project:ProcAudit-Engine
 */
#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint64_t pid;
    uint64_t ram_bytes;
    uint64_t thread_count;
    uint64_t open_handles;
} ProcessTelemetry;

/**
 * Parses telemetry buffer to isolate zombie/ghost processes holding RAM with 0 threads.
 * Skips trusted kernel PIDs (4, 76).
 */
int32_t process_telemetry_stream(const ProcessTelemetry* dataset, int32_t total_rows, uint64_t* alert_buffer , int32_t max_alerts,int32_t* total_alerts) { //function signature
    
    // Hard fail on invalid memory addresses(Null Pointers)
    if (!dataset || !alert_buffer || !total_alerts) {
        return -1;
    }

    // Block empty or corrupted stream sizes (fix)AND validate buffer capacity
    if (total_rows <= 0 ||  max_alerts <= 0) {
        *total_alerts = 0;
        return -2; 
    }

    int32_t tracked_count = 0;
    int32_t idx = 0;

    // Process stream using direct array indexing instead of pointer walking #O(1) memory allocation
    while (idx < total_rows) {
        uint64_t target_pid= dataset[idx].pid;

        // OPTIMIZATION: Branch Prediction Bypass
        // Check whitelist FIRST. If matched, jump instantly to next cycle.
        // Saves CPU from evaluating thread_count/ram_bytes on benign processes.
        if (target_pid == 4 || target_pid == 76) {
            idx++;
            continue; 
        }
        
        // Target anomalous state: inactive threads but unreleased memory
        if (dataset[idx].thread_count == 0 && dataset[idx].ram_bytes > 0) {
            
            //PATCH: strict bound checkig executed
            if (tracked_count >= max_alerts){
                break; //halt alert collection
            }
            alert_buffer[tracked_count] = target_pid;
            tracked_count++;
            }
        
        idx++;
    }

    *total_alerts = tracked_count;//Dereference pointer to write back final count
    return 0; // Execution completed cleanly
}
