/*This header file defines the public interface and core data model for the process-level
correlation subsystem, and it reflects a deliberately bounded, low-overhead design
suitable for real-time monitoring agents operating in resource-constrained or latency-
sensitive enviroments.The inclusion guards prevent multiple inclusion issues, while the
use of <stdint.h>, <sys/types.h>, and <stdbool.h> ensures precise control over
integer widths, process identifiers, and boolean semantics, reinforcing portability across
Unix-like systems. The macro CORR_MAX_TRACKED sets a hard upper limit on the number of
simultaneously tracked processes, signaling an intentional design choice: rather than
relying on dynamic memory allocation, the engine uses a fixed-size array for deterministic
memory usage and predictable performance characteristics. This is especially appropriate
in monitoring daemons where unbounded growth could become a stability risk.
The process_risk_t structure encapsulates all state associated with a tracked process (or
thread), combining identity (pid, tid), metadata (comm), dynamic risk scoring
(anomaly_score), behavioral counters (suspicious_samples, total_samples), temporal
tracking (last_seen_ns), and lifecycle state (active). This design demonstrates a clear
separation between identity, scoring, and time-based management. The use of a bounded
comm[64] buffer avoids heap allocation while still preserving meaningful process
identification data obtained from /proc, and the inclusion of both suspicious and total
sample counters suggests that the system is capable of supporting richer analytics or
escalation logic beyond simple score comparison. Storing timestamps in nanoseconds
(uint64_t) indicates that the engine is designed to integrate with high-resolution
telemetry pipelines, maintaining consistent time granularity throughout the system.
The correlation_engine_t structure aggregates all tracked entries and includes
configuration parameters that govern temporal behavior: decay_factor controls
exponential risk attenuation over time, while window_sec defines the inactivity threshold
beyond which processes are deactivated. The presence of a count field tracking how
many slots are currently initialized enables efficient iteration without scanning the entire
maximum capacity unnecessarily. Together, these elements form a compact but expressive
in-memory model for process-centric anomaly aggregation.
The function prototypes establish a disciplined lifecycle for the engine: initialization with
configurable decay behavior, incremental updates as new anomaly scores arrive, periodic
decay to enforce temporal relevance, and query functions for lookup and top-risk retrieval.
The design encourages periodic invocation of correlation_decay, indicating that time-
based risk attenuation is a core part of the model rather than an afterthought. The lookup
and top-risk functions provide read-only access patterns, suggesting that external
components—such as alert managers or dashboards—can safely query correlation results
without mutating state. Finally, correlation_resolve_comm formalizes integration with the
Linux /proc filesystem to enrich entries with human-readable process names, reinforcing
operational transparency.
Overall, this header defines a deterministic, memory-bounded, and temporally aware risk
aggregation layer that transforms raw anomaly scores into actionable, process-level
intelligence. Its structure emphasizes predictability, performance stability, and extensibility,
making it well-suited for integration into a production-grade performance monitoring or
security anomaly detection framework operating at the system level.
*/

#ifndef CPUGUARD_CORRELATION_H
#define CPUGUARD_CORRELATION_H

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>

#define CORR_MAX_TRACKED 256

typedef struct {
    pid_t    pid;
    pid_t    tid;
    char     comm[64];
    float    anomaly_score;
    uint64_t suspicious_samples;
    uint64_t total_samples;
    uint64_t last_seen_ns;
    bool     active;
} process_risk_t;

typedef struct {
    process_risk_t entries[CORR_MAX_TRACKED];
    size_t         count;
    double         decay_factor;
    uint32_t       window_sec;
} correlation_engine_t;


void correlation_init(correlation_engine_t *eng,
                      double decay_factor,
                      uint32_t window_sec);


void correlation_update(correlation_engine_t *eng,
                        pid_t pid, pid_t tid,
                        float score, uint64_t timestamp_ns);


void correlation_decay(correlation_engine_t *eng, uint64_t now_ns);


const process_risk_t *correlation_lookup(const correlation_engine_t *eng,
                                          pid_t pid);


const process_risk_t *correlation_top_risk(const correlation_engine_t *eng);


void correlation_resolve_comm(process_risk_t *entry);

#endif 
