/*This main file is essentially the orchestration layer of CPU Guardian, wiring together
configuration parsing, PMU access, telemetry collection, anomaly detection, correlation,
logging, and optional ML offloading into a cohesive real-time detection pipeline. It is
structured like a production-grade daemon: clearly divided into initialization, learning,
detection, and cleanup phases, with strong attention to privilege handling, fault tolerance,
and graceful shutdown.
At startup, the program prints a banner and initializes configuration with defaults, then
parses command-line arguments. A subtle but important safeguard ensures that both
pid=-1 and cpu=-1 are never passed simultaneously to the PMU layer, defaulting instead
to monitoring the current process. There is also a dedicated PMU test mode that opens
hardware counters, reads them once, and exits—this is extremely practical for debugging
environments where perf_event_open may fail due to VM restrictions or
perf_event_paranoid settings. The error messages are explicit and operationally helpful,
showing that this tool is meant to be deployed in real-world Linux systems where PMU
access is often misconfigured.
Signal handling is implemented using sigaction, setting a global atomic shutdown flag.
This allows the main loops to terminate cleanly without unsafe signal-side logic. The
logger is initialized early, and from that point onward the program consistently uses
structured logging for observability. The ring buffer is then allocated as a decoupling
mechanism between the telemetry thread and the detection logic, preventing sampling
jitter from blocking analysis.
The telemetry engine is started while still running with elevated privileges, since opening
PMU counters typically requires root access. Notably, privileges are intentionally dropped
only after the learning phase, which is a strong security-conscious design choice: hardware
access is established first, then the detection phase runs with reduced privileges,
minimizing risk exposure.
The runtime is split into two conceptual phases. In Phase 1 (Learning), samples are
consumed from the ring buffer and fed into the anomaly engine to build a statistical
baseline. This continues for a configurable duration, and if no samples are collected, the
program aborts with a clear diagnostic—preventing meaningless detection on an empty
baseline. During learning, telemetry can optionally be streamed to a Python ML engine
over a non-blocking Unix socket, but failure to connect does not stop the C-only detection
pipeline.
After baseline finalization, the program enters Phase 2 (Detection), which runs
continuously until shutdown. Each telemetry sample is analyzed, producing z-scores and a
composite anomaly score. If anomaly flags are set, severity is derived from score
thresholds and burst patterns, and correlation logic updates process-level risk using
exponential smoothing and time decay. The highest-risk process is resolved for contextual
logging, and structured JSON alerts are emitted through the logger subsystem. Verbose
mode additionally prints detailed z-score diagnostics, which is valuable for tuning
thresholds in research or testing environments.
Periodic maintenance tasks are embedded cleanly within the loop: correlation decay runs
once per second, and verbose status summaries are printed every ten seconds. These
summaries include anomaly percentage and ring buffer fill level, giving operators insight
into runtime health and detection frequency without external tooling.
Finally, the cleanup path ensures orderly shutdown: IPC socket closure, telemetry stop,
anomaly engine destruction, ring buffer release, and logger teardown. A final summary
line prints total samples and anomaly count, reinforcing the tool’s operational
transparency.
Overall, this main function demonstrates strong systems engineering principles: staged
initialization, privilege minimization, lock-free decoupling via ring buffers, time-aware
anomaly modeling, structured logging, best-effort ML integration, and graceful
degradation. It reads like the control plane of a serious real-time side-channel detection
engine rather than a simple prototype.
*/

#ifndef __linux__
#error "cpu-guardian requires Linux x86_64 (perf_event_open, /proc, sched_setaffinity)"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/types.h>
#include <errno.h>

#include "config.h"
#include "pmu.h"
#include "telemetry.h"
#include "ringbuffer.h"
#include "anomaly.h"
#include "correlation.h"
#include "logger.h"
#include "ipc_socket.h"

static volatile sig_atomic_t g_shutdown = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void print_banner(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║       CPU Guardian - Side-Channel Detector      ║\n");
    printf("║       Real-Time PMU Anomaly Detection Engine    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
}

static void drop_privileges(void)
{
    if (geteuid() != 0) return;

    const char *sudo_uid = getenv("SUDO_UID");
    const char *sudo_gid = getenv("SUDO_GID");

    if (sudo_uid && sudo_gid) {
        uid_t uid = (uid_t)strtoul(sudo_uid, NULL, 10);
        gid_t gid = (gid_t)strtoul(sudo_gid, NULL, 10);

        if (setgid(gid) != 0) {
            perror("[main] setgid");
        }
        if (setuid(uid) != 0) {
            perror("[main] setuid");
        }
        fprintf(stderr, "[main] dropped privileges to uid=%d gid=%d\n",
                uid, gid);
    }
}

int main(int argc, char *argv[])
{
    print_banner();

    
    guardian_config_t cfg;
    config_set_defaults(&cfg);

    if (config_parse_args(&cfg, argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    
    if (cfg.target_pid == -1 && cfg.target_cpu == -1) {
        cfg.target_pid = 0;
        cfg.target_cpu = -1;
    }

    if (cfg.verbose) {
        config_dump(&cfg);
    }

    
    if (cfg.pmu_test) {
        pmu_context_t pmu;
        if (pmu_open(&pmu, cfg.target_cpu, cfg.target_pid) != 0) {
            fprintf(stderr, "[cpu-guardian] PMU test failed: could not open counters\n");
            fprintf(stderr, "[cpu-guardian] If errno=2 (ENOENT): VM may not expose PMU; try bare metal or enable PMU passthrough.\n");
            fprintf(stderr, "[cpu-guardian] If errno=13 (EACCES): run with sudo and ensure perf_event_paranoid <= 2 (e.g. sudo sysctl kernel.perf_event_paranoid=2)\n");
            return EXIT_FAILURE;
        }
        pmu_reading_t r;
        if (pmu_read(&pmu, &r) != 0) {
            fprintf(stderr, "[cpu-guardian] PMU test failed: read failed\n");
            pmu_close(&pmu);
            return EXIT_FAILURE;
        }
        printf("PMU raw read (counters open: %d):\n", pmu_count_open(&pmu));
        printf("  cycles              = %lu\n", (unsigned long)r.cycles);
        printf("  instructions        = %lu\n", (unsigned long)r.instructions);
        printf("  cache_references    = %lu\n", (unsigned long)r.cache_references);
        printf("  cache_misses        = %lu\n", (unsigned long)r.cache_misses);
        printf("  branch_instructions = %lu\n", (unsigned long)r.branch_instructions);
        printf("  branch_misses       = %lu\n", (unsigned long)r.branch_misses);
        pmu_close(&pmu);
        printf("[cpu-guardian] PMU test OK\n");
        return EXIT_SUCCESS;
    }

    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);


    logger_t logger;
    if (logger_init(&logger, cfg.log_file,
                    cfg.log_to_file, cfg.log_to_syslog,
                    cfg.alert_cooldown_sec) != 0) {
        fprintf(stderr, "[main] failed to initialise logger\n");
        return EXIT_FAILURE;
    }

    logger_info(&logger, "starting up (interval=%uus, learning=%us, z=%.2f)",
                cfg.sampling_interval_us, cfg.learning_duration_sec,
                cfg.z_threshold);

    
    ringbuffer_t rb;
    if (ringbuffer_init(&rb, cfg.ringbuffer_capacity) != 0) {
        fprintf(stderr, "[main] failed to allocate ring buffer\n");
        logger_destroy(&logger);
        return EXIT_FAILURE;
    }

    
    telemetry_engine_t telemetry;
    telemetry_init(&telemetry, cfg.sampling_interval_us,
                   cfg.target_cpu, cfg.target_pid);

    if (telemetry_start(&telemetry, &rb) != 0) {
        fprintf(stderr, "[main] failed to start telemetry engine\n");
        ringbuffer_destroy(&rb);
        logger_destroy(&logger);
        return EXIT_FAILURE;
    }

    logger_info(&logger, "telemetry engine started on cpu=%d pid=%d",
                cfg.target_cpu, cfg.target_pid);

    
    

    
    anomaly_engine_t anomaly;
    if (anomaly_init(&anomaly, cfg.z_threshold, cfg.burst_window) != 0) {
        fprintf(stderr, "[main] failed to init anomaly engine\n");
        telemetry_stop(&telemetry);
        ringbuffer_destroy(&rb);
        logger_destroy(&logger);
        return EXIT_FAILURE;
    }

    
    correlation_engine_t corr;
    correlation_init(&corr, cfg.risk_decay_factor, cfg.correlation_window_sec);

    
    int ml_sock_fd = -1;
    if (cfg.enable_ml_output) {
        ml_sock_fd = ipc_socket_init(cfg.socket_path);
        if (ml_sock_fd >= 0) {
            logger_info(&logger, "ML IPC connected: %s", cfg.socket_path);
        } else {
            logger_info(&logger, "ML IPC unavailable (%s) — using C-only detection",
                        cfg.socket_path);
        }
    }

    
    logger_info(&logger, "entering learning phase (%u seconds)...",
                cfg.learning_duration_sec);

    uint64_t learn_start = now_ns();
    uint64_t learn_duration_ns = (uint64_t)cfg.learning_duration_sec * 1000000000ULL;
    uint64_t learn_samples = 0;

    while (!g_shutdown) {
        uint64_t elapsed = now_ns() - learn_start;
        if (elapsed >= learn_duration_ns) break;

        telemetry_sample_t sample;
        if (ringbuffer_pop(&rb, &sample)) {
            anomaly_learn(&anomaly, &sample);
            if (ml_sock_fd >= 0)
                ipc_socket_send(ml_sock_fd, &sample);
            learn_samples++;
        } else {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000 };
            nanosleep(&ts, NULL);
        }
    }

    uint64_t total_samples   = 0;
    uint64_t anomaly_samples = 0;
    uint64_t last_decay_ns   = 0;
    uint64_t last_status_ns  = 0;

    if (g_shutdown) {
        goto cleanup;
    }

    if (learn_samples == 0) {
        fprintf(stderr, "[cpu-guardian] FATAL: No PMU samples collected during learning — aborting\n");
        fprintf(stderr, "[cpu-guardian] Check PMU access (perf_event_paranoid, VM restrictions) or run with -T to test counters\n");
        telemetry_stop(&telemetry);
        anomaly_destroy(&anomaly);
        ringbuffer_destroy(&rb);
        logger_destroy(&logger);
        return EXIT_FAILURE;
    }

    anomaly_finalize_baseline(&anomaly);
    logger_info(&logger, "learning complete: %lu samples collected",
                (unsigned long)learn_samples);

    
    drop_privileges();

    
    logger_info(&logger, "entering detection phase...");

    last_decay_ns  = now_ns();
    last_status_ns = now_ns();

    while (!g_shutdown) {
        telemetry_sample_t sample;
        if (!ringbuffer_pop(&rb, &sample)) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };
            nanosleep(&ts, NULL);
            continue;
        }

        total_samples++;

        anomaly_result_t result;
        anomaly_detect(&anomaly, &sample, &result);

        if (ml_sock_fd >= 0)
            ipc_socket_send(ml_sock_fd, &sample);

    
        log_level_t level = ALERT_INFO;
        if (result.anomaly_flags != 0) {
            anomaly_samples++;

            if (result.composite_score > 0.8 ||
                (result.anomaly_flags & ANOMALY_BURST_PATTERN)) {
                level = ALERT_CRITICAL;
            } else if (result.composite_score > 0.5) {
                level = ALERT_WARNING;
            } else {
                level = ALERT_INFO;
            }

            const char *reason = anomaly_flags_str(result.anomaly_flags);

        
            pid_t p = cfg.target_pid > 0 ? cfg.target_pid : getpid();
            correlation_update(&corr, p, 0,
                               (float)result.composite_score,
                               sample.timestamp_ns);

            const process_risk_t *top = correlation_top_risk(&corr);
            const char *comm = top ? top->comm : "system";

            logger_alert(&logger, level, sample.timestamp_ns,
                         p, comm, result.composite_score, reason);

            if (cfg.verbose) {
                fprintf(stderr,
                    "[detect] z_cmr=%.2f z_bmr=%.2f z_ipc=%.2f "
                    "score=%.4f sustained=%u flags=%s\n",
                    result.z_cache_miss,
                    result.z_branch_miss,
                    result.z_ipc,
                    result.composite_score,
                    result.sustained_count,
                    reason);
            }
        }

    
        uint64_t current = now_ns();
        if (current - last_decay_ns > 1000000000ULL) {
            correlation_decay(&corr, current);
            last_decay_ns = current;
        }

    
        if (cfg.verbose && (current - last_status_ns > 10000000000ULL)) {
            double anomaly_pct = total_samples > 0
                ? (double)anomaly_samples / (double)total_samples * 100.0
                : 0.0;
            logger_info(&logger,
                "status: %lu samples, %lu anomalies (%.2f%%), rb_fill=%zu",
                (unsigned long)total_samples,
                (unsigned long)anomaly_samples,
                anomaly_pct,
                ringbuffer_count(&rb));
            last_status_ns = current;
        }
    }

cleanup:
    logger_info(&logger, "shutting down...");

    ipc_socket_close(ml_sock_fd);
    telemetry_stop(&telemetry);
    anomaly_destroy(&anomaly);
    ringbuffer_destroy(&rb);
    logger_destroy(&logger);

    printf("\n[cpu-guardian] exited cleanly. "
           "Total samples: %lu, Anomalies: %lu\n",
           (unsigned long)total_samples,
           (unsigned long)anomaly_samples);

    return EXIT_SUCCESS;
}
