/*This header defines the public abstraction layer for interacting with hardware performance 
monitoring counters (PMU) inside CPU Guardian, and it reflects a clean, structured separation 
between low-level perf mechanics and the rest of the detection engine. The design is intentionally 
minimal but carefully organized to preserve ordering, grouping semantics, and critical-versus-optional 
counter priorities.
At the top, PMU_NUM_COUNTERS fixes the total number of tracked counters to six, enforcing a static, 
predictable layout. The pmu_counter_idx_t enum defines the exact ordering of these counters, explicitly 
noting that critical metrics—CYCLES and INSTRUCTIONS—come first. This ordering is not cosmetic; it encodes 
priority directly into the index structure. Since these two counters are essential for computing IPC (instructions 
per cycle) and forming the statistical baseline, the implementation guarantees they are opened first 
and treated as mandatory. The remaining counters (cache misses, branch misses, branch instructions, cache 
references) are considered supplementary and may fail without aborting initialization.
The pmu_context_t structure encapsulates the runtime state of an open PMU session. It stores file descriptors 
for each counter slot, along with the associated CPU, PID, and a group_fd used to synchronize events under a single 
leader. Using a grouped configuration ensures that enabling, disabling, and resetting counters can be 
performed atomically via ioctl calls on the group leader. By keeping all file descriptors in a fixed-size array, 
the design avoids dynamic allocation and makes cleanup straightforward and deterministic.
The pmu_reading_t structure represents a normalized snapshot of counter values after scaling and correction. 
Importantly, it abstracts away perf-specific details such as time multiplexing or raw read formats. Consumers 
of this API receive clean 64-bit values for cycles, instructions, and related metrics, without needing to 
understand perf’s internal semantics. Unopened counters are guaranteed to remain zero, which simplifies 
downstream anomaly calculations.
The function prototypes define a clear lifecycle: pmu_open initializes and validates counter access, 
ensuring at least the critical metrics are available; pmu_count_open provides visibility into how many counters 
are active; pmu_read collects scaled values; and pmu_reset, pmu_enable, and pmu_disable expose explicit control 
over measurement state. Finally, pmu_close guarantees safe teardown of all descriptors.
Overall, this header establishes a disciplined and hardware-aware interface that isolates the rest of the 
system from perf-specific complexity while enforcing strict guarantees about critical metric availability. 
It forms a stable, deterministic foundation for high-resolution telemetry in a real-time anomaly 
detection engine.
*/

#ifndef CPUGUARD_PMU_H
#define CPUGUARD_PMU_H

#include <stdint.h>
#include <sys/types.h>

#define PMU_NUM_COUNTERS 6


typedef enum {
    PMU_IDX_CYCLES        = 0,
    PMU_IDX_INSTRUCTIONS  = 1,
    PMU_IDX_CACHE_MISS    = 2,
    PMU_IDX_BRANCH_MISS   = 3,
    PMU_IDX_BRANCH_INST   = 4,
    PMU_IDX_CACHE_REF     = 5,
} pmu_counter_idx_t;

typedef struct {
    int    fds[PMU_NUM_COUNTERS];
    int    cpu;
    pid_t  pid;
    int    group_fd;
} pmu_context_t;

typedef struct {
    uint64_t cache_references;
    uint64_t cache_misses;
    uint64_t branch_instructions;
    uint64_t branch_misses;
    uint64_t instructions;
    uint64_t cycles;
} pmu_reading_t;


int pmu_open(pmu_context_t *ctx, int cpu, pid_t pid);


int pmu_count_open(const pmu_context_t *ctx);


int pmu_read(pmu_context_t *ctx, pmu_reading_t *out);

int pmu_reset(pmu_context_t *ctx);
int pmu_enable(pmu_context_t *ctx);
int pmu_disable(pmu_context_t *ctx);
void pmu_close(pmu_context_t *ctx);

#endif 
