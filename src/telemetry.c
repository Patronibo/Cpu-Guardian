/*This telemetry module is the real-time sampling engine of CPU Guardian, acting as the 
bridge between low-level PMU counters and the higher-level anomaly detection pipeline. 
It is designed as a dedicated background thread that periodically samples hardware 
counters, computes deltas and derived metrics, and streams normalized telemetry samples 
into a lock-free ring buffer. The structure reflects a strong emphasis on determinism, 
low overhead, and clean separation of responsibilities.
The implementation begins with strict Linux enforcement and uses `CLOCK_MONOTONIC_RAW` 
for timestamps, which is a deliberate choice. Unlike `CLOCK_MONOTONIC`, the RAW variant 
avoids time adjustments from NTP or frequency scaling corrections, ensuring stable and 
monotonic nanosecond-level timing—critical for performance telemetry.
CPU affinity is handled explicitly through `sched_setaffinity`. The `pin_to_cpu` helper 
allows the sampling thread to be bound to a specific core, reducing scheduler migration 
noise and cache invalidation effects. This is especially important when measuring CPU events, 
as migration across cores can distort counter consistency or introduce jitter.
The heart of the module is `sampling_loop`. After initializing PMU counters and enabling 
them as a group, the thread sleeps for a configurable interval using `nanosleep`, based 
on microsecond precision. Instead of reporting raw counter values, the engine computes 
deltas between successive readings. This delta-based approach converts cumulative 
hardware counters into per-interval metrics, which are far more meaningful for anomaly 
detection and rate-based analysis.
The `compute_derived` function transforms raw deltas into higher-level indicators such as 
cache miss rate, branch miss rate, and IPC (instructions per cycle). Each metric includes 
safe division guards to prevent division-by-zero errors. The resulting `telemetry_sample_t` 
contains both raw deltas and normalized floating-point ratios, making it immediately usable 
by statistical or ML-based consumers.
Importantly, the sampling thread never blocks on downstream processing. It pushes samples 
into the ring buffer without waiting; if the buffer is full, the sample is effectively dropped. 
This design choice protects the monitoring loop from backpressure and ensures that telemetry 
collection remains stable even if the consumer lags.
Lifecycle management is clean and predictable. `telemetry_init` prepares the configuration,
`telemetry_start` allocates thread arguments and launches the worker thread, and `telemetry_stop` 
safely terminates execution using a running flag and `pthread_join`. PMU resources are properly 
disabled and closed before exit, preventing descriptor leaks.
Overall, this module demonstrates a production-ready design: CPU pinning for measurement 
stability, delta computation for meaningful metrics, non-blocking data handoff, and disciplined 
resource management. It serves as a reliable, low-noise telemetry backbone for real-time CPU 
anomaly detection.
*/

#ifndef __linux__
#error "cpu-guardian requires Linux x86_64"
#endif

#include "telemetry.h"
#include "pmu.h"
#include "ringbuffer.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>

typedef struct {
    telemetry_engine_t *engine;
    ringbuffer_t       *rb;
} thread_arg_t;

static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int pin_to_cpu(int cpu)
{
    if (cpu < 0) return 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        fprintf(stderr, "[telemetry] failed to pin to CPU %d: %s\n",
                cpu, strerror(errno));
        return -1;
    }
    return 0;
}

static void compute_derived(telemetry_sample_t *s, const pmu_reading_t *r)
{
    s->cache_references    = r->cache_references;
    s->cache_misses        = r->cache_misses;
    s->branch_instructions = r->branch_instructions;
    s->branch_misses       = r->branch_misses;
    s->instructions        = r->instructions;
    s->cycles              = r->cycles;

    s->cache_miss_rate  = (r->instructions > 0)
        ? (float)r->cache_misses / (float)r->instructions
        : 0.0f;

    s->branch_miss_rate = (r->branch_instructions > 0)
        ? (float)r->branch_misses / (float)r->branch_instructions
        : 0.0f;

    s->ipc = (r->cycles > 0)
        ? (float)r->instructions / (float)r->cycles
        : 0.0f;
}

static void *sampling_loop(void *arg)
{
    thread_arg_t *ta = (thread_arg_t *)arg;
    telemetry_engine_t *eng = ta->engine;
    ringbuffer_t *rb = ta->rb;
    free(ta);

    pin_to_cpu(eng->cpu);

    pmu_context_t pmu;
    if (pmu_open(&pmu, eng->cpu, eng->pid) != 0) {
        fprintf(stderr, "[telemetry] failed to open PMU counters\n");
        return NULL;
    }
    fprintf(stderr, "[telemetry] PMU counters initialized successfully (%d open)\n",
            pmu_count_open(&pmu));

    if (pmu_enable(&pmu) != 0) {
        fprintf(stderr, "[telemetry] failed to enable PMU counters\n");
        pmu_close(&pmu);
        return NULL;
    }

    struct timespec sleep_ts = {
        .tv_sec  = eng->interval_us / 1000000,
        .tv_nsec = (eng->interval_us % 1000000) * 1000L
    };

    pmu_reading_t prev = {0};
    bool have_prev = false;

    while (eng->running) {
        nanosleep(&sleep_ts, NULL);

        pmu_reading_t cur;
        if (pmu_read(&pmu, &cur) != 0) continue;

        if (have_prev) {
            pmu_reading_t delta = {
                .cache_references   = cur.cache_references   - prev.cache_references,
                .cache_misses       = cur.cache_misses       - prev.cache_misses,
                .branch_instructions = cur.branch_instructions - prev.branch_instructions,
                .branch_misses      = cur.branch_misses      - prev.branch_misses,
                .instructions       = cur.instructions       - prev.instructions,
                .cycles             = cur.cycles             - prev.cycles,
            };

            telemetry_sample_t sample;
            memset(&sample, 0, sizeof(sample));
            sample.timestamp_ns = get_timestamp_ns();
            compute_derived(&sample, &delta);

            ringbuffer_push(rb, &sample);
        }

        prev = cur;
        have_prev = true;
    }

    pmu_disable(&pmu);
    pmu_close(&pmu);
    return NULL;
}

void telemetry_init(telemetry_engine_t *eng,
                    uint32_t interval_us,
                    int cpu, pid_t pid)
{
    if (!eng) return;
    memset(eng, 0, sizeof(*eng));
    eng->running     = false;
    eng->interval_us = interval_us;
    eng->cpu         = cpu;
    eng->pid         = pid;
}

int telemetry_start(telemetry_engine_t *eng, void *ringbuffer)
{
    if (!eng || !ringbuffer) return -1;

    thread_arg_t *ta = malloc(sizeof(thread_arg_t));
    if (!ta) return -1;
    ta->engine = eng;
    ta->rb     = (ringbuffer_t *)ringbuffer;

    eng->running = true;

    if (pthread_create(&eng->thread, NULL, sampling_loop, ta) != 0) {
        free(ta);
        eng->running = false;
        return -1;
    }

    return 0;
}

void telemetry_stop(telemetry_engine_t *eng)
{
    if (!eng) return;
    eng->running = false;
    pthread_join(eng->thread, NULL);
}
