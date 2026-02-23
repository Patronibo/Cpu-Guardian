/*This header file defines the public interface and core data structures of the anomaly
detection subsystem in a clean, modular, and production-oriented manner, effectively
separating statistical logic from telemetry collection while exposing only what is necessary
for external integration. At the top level, the inclusion guards (#ifndef
CPUGUARD_ANOMALY_H) prevent multiple inclusion issues, which is standard but critical in
larger C projects where cross-module dependencies can easily introduce compilation
conflicts. The inclusion of <stdint.h>, <stdbool.h>, and <stddef.h> ensures that all
integer widths, boolean semantics, and size abstractions are explicit and portable across
platforms, reinforcing the system-level design mindset. The dependency on
"telemetry.h" signals that this module operates purely on pre-collected hardware
performance metrics, maintaining a clean separation of concerns between data acquisition 
and statistical evaluation.
The anomaly_flags_t enum is particularly well-designed: it encodes anomaly types as bit
flags rather than simple enumerated constants, enabling multiple anomaly conditions to
coexist within a single result. This bitmask approach is efficient, extensible, and appropriate
for low-level systems code where compact state representation matters. Each flag reflects
a specific microarchitectural or behavioral pattern—cache miss spikes, branch miss spikes,
IPC collapse, burst behavior, and oscillation—indicating that the engine is not merely
threshold-based but pattern-aware. The baseline_profile_t structure encapsulates the
statistical reference model, holding mean and standard deviation values for each
monitored metric along with a sample_count and a ready flag, which acts as a guard to
prevent detection before proper initialization. This design enforces a clear lifecycle: learn
first, finalize baseline, then detect.
The anomaly_result_t structure represents the analytical output of the engine and is
carefully structured to provide both raw statistical insight (z-scores per metric) and higher-
level interpretation (composite score and bitwise anomaly flags). The inclusion of a
normalized composite_score in the range 0.0 to 1.0 suggests that the engine is intended
for integration into alerting systems or visualization layers where a bounded severity
metric is useful. The sustained_count field captures temporal continuity, allowing
downstream logic to differentiate between isolated anomalies and sustained abnormal
behavior. The core engine structure, anomaly_engine_t, combines configuration
parameters (z_threshold, burst_window), the computed baseline, internal accumulators
for online mean and variance computation, and state for burst and oscillation detection.
The presence of both first-order and second-order accumulators (sum_* and sum_*2)
confirms that the system uses a streaming statistical model without storing historical
samples, which is memory-efficient and appropriate for long-running monitoring
processes. The sliding window buffer (recent_cmr) and associated indices provide
bounded memory usage for temporal pattern detection, demonstrating deliberate
resource control.
The function prototypes define a clear and disciplined API lifecycle: initialization,
destruction, learning phase input, baseline finalization, runtime detection, and human-
readable flag formatting. The explicit documentation comments above each function
reinforce intended usage order and constraints, reducing misuse risk. Overall, this header
reflects a well-structured systems component with strong attention to modularity,
statistical rigor, extensibility, and runtime efficiency, making it suitable for integration into a
performance monitoring or security-focused CPU telemetry analysis framework.
*/ 

#ifndef CPUGUARD_ANOMALY_H
#define CPUGUARD_ANOMALY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "telemetry.h"

typedef enum {
    ANOMALY_NONE              = 0,
    ANOMALY_CACHE_MISS_SPIKE  = (1 << 0),
    ANOMALY_BRANCH_MISS_SPIKE = (1 << 1),
    ANOMALY_IPC_COLLAPSE      = (1 << 2),
    ANOMALY_BURST_PATTERN     = (1 << 3),
    ANOMALY_OSCILLATION       = (1 << 4),
} anomaly_flags_t;

typedef struct {
    double mean_cache_miss_rate;
    double std_cache_miss_rate;
    double mean_branch_miss_rate;
    double std_branch_miss_rate;
    double mean_ipc;
    double std_ipc;
    size_t sample_count;
    bool   ready;
} baseline_profile_t;

typedef struct {
    double z_cache_miss;
    double z_branch_miss;
    double z_ipc;
    double composite_score;       
    uint32_t anomaly_flags;
    uint32_t sustained_count;     
} anomaly_result_t;

typedef struct {
    baseline_profile_t baseline;
    double             z_threshold;
    uint32_t           burst_window;

    
    double  sum_cmr, sum_cmr2;
    double  sum_bmr, sum_bmr2;
    double  sum_ipc, sum_ipc2;
    size_t  n;

    
    uint32_t consecutive_anomalies;
    float   *recent_cmr;          
    size_t   recent_idx;
    size_t   recent_cap;
} anomaly_engine_t;


int anomaly_init(anomaly_engine_t *eng, double z_threshold, uint32_t burst_window);


void anomaly_destroy(anomaly_engine_t *eng);


void anomaly_learn(anomaly_engine_t *eng, const telemetry_sample_t *s);


void anomaly_finalize_baseline(anomaly_engine_t *eng);


void anomaly_detect(anomaly_engine_t *eng,
                    const telemetry_sample_t *s,
                    anomaly_result_t *result);


const char *anomaly_flags_str(uint32_t flags);

#endif 
