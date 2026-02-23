/*This header defines the public interface of the telemetry subsystem, which serves as the 
structured data producer for CPU Guardian’s monitoring pipeline. It separates the representation 
of collected metrics from the mechanics of sampling, resulting in a clean and modular design.
The telemetry_sample_t structure represents a single normalized measurement snapshot. It combines 
both raw hardware-derived counters (cycles, instructions, cache references, cache misses, 
branch instructions, branch misses) and computed metrics such as cache miss rate, branch miss 
rate, and IPC. Including derived values directly in the sample structure is an important architectural 
decision: it shifts lightweight computation into the sampling layer so that downstream 
consumers—whether logging, IPC transmission, or ML inference—can operate without recalculating 
ratios. The inclusion of a nanosecond-resolution timestamp ensures each sample is temporally 
precise and suitable for time-series analysis.
The telemetry_engine_t structure encapsulates the runtime state of the sampling system. It owns 
the background thread handle, a running flag used to control the sampling loop, the sampling 
interval in microseconds, and optional CPU/PID targeting parameters. The presence of both cpu 
and pid fields allows flexible monitoring modes, such as system-wide per-core sampling or 
process-specific profiling. Using a dedicated thread keeps sampling asynchronous and prevents 
blocking the main execution flow.
The API enforces a clear lifecycle. telemetry_init configures the engine but does not start 
it, ensuring separation between configuration and execution. telemetry_start launches the 
sampling thread and begins pushing samples into the provided ring buffer, keeping the engine 
loosely coupled to its consumer. telemetry_stop signals termination and joins the thread, guaranteeing 
orderly shutdown and preventing orphaned worker threads.
Overall, this header establishes a focused and production-ready telemetry interface. It abstracts 
hardware performance sampling into a predictable, thread-driven component that emits structured, 
analysis-ready data at controlled intervals, forming a reliable foundation for real-time anomaly 
detection or performance monitoring.
*/

#ifndef CPUGUARD_TELEMETRY_H
#define CPUGUARD_TELEMETRY_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>

typedef struct {
    uint64_t timestamp_ns;
    uint64_t cache_references;
    uint64_t cache_misses;
    uint64_t branch_instructions;
    uint64_t branch_misses;
    uint64_t cycles;
    uint64_t instructions;
    float    cache_miss_rate;
    float    branch_miss_rate;
    float    ipc;
} telemetry_sample_t;

typedef struct {
    pthread_t           thread;
    volatile bool       running;
    uint32_t            interval_us;
    int                 cpu;
    pid_t               pid;
} telemetry_engine_t;


void telemetry_init(telemetry_engine_t *eng,
                    uint32_t interval_us,
                    int cpu, pid_t pid);


int telemetry_start(telemetry_engine_t *eng, void *ringbuffer);


void telemetry_stop(telemetry_engine_t *eng);

#endif
