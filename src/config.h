/*This header file defines the configuration contract for the CPU Guardiadn system in a clean,
forward-looking, and deployment-aware manner, encapsulating all runtime-tunable 
parameters into a single structured abstraction while preserving portability and clarity. The
inclusion guards prevent multiple definition conflicts, which is essential in modular C
projects, and the  inclusion of <stdint.h>, <stdbool.h>, and <sys/types.h> ensures that
integer widths, boolean semantics, and system-level types like pid_t remain consistent
across platforms. The defined constants CONFIG_MAX_PATH and CONFIG_MAX_LINE
introduce explicit upper bounds for file paths and configuration lines, reflecting a
defensive programming approach that avoids dynamic allocation for common
configuration operations and reduces the risk of buffer overflow vulnerabilities.
At the core of this interface lies the guardian_config_t structure, which aggregates
operational, statistical, logging, and behavioral parameters into a single cohesive unit. The
presence of fields such as sampling_interval_us, learning_duration_sec, and
z_threshold reveals that the system is designed around a statistical anomaly detection
pipeline with tunable sensitivity and training duration. Parameters like burst_window,
correlation_window_sec, and alert_cooldown_sec indicate that anomaly evaluation is
not purely instantaneous but considers temporal dynamics, sustained patterns, and alert
rate limiting, suggesting that the overall architecture accounts for noise filtering and event
correlation rather than simplistic threshold triggers. The inclusion of ringbuffer_capacity
demonstrates foresight regarding bounded memory usage in streaming telemetry
contexts, while risk_decay_factor implies a probabilistic or weighted scoring mechanism
where anomaly influence fades over time, a concept commonly used in adaptive risk
modeling systems.
Operational flexibility is evident in fields such as target_cpu and target_pid, enabling
both system-wide and scoped monitoring modes, and the boolean per_process_mode
further hints at multi-context analysis capability. Logging is treated as a first-class concern,
with both file-based and syslog output supported, and a fixed-size log_file buffer
ensures predictable memory layout without heap allocation. The addition of socket_path
and enable_ml_output suggests extensibility toward inter-process communication and
potential machine-learning-based output pipelines, indicating that the system may
integrate with external analytics components or real-time dashboards. The presence of a
pmu_test flag reflects awareness of hardware performance counter constraints, especially
relevant in virtualized or permission-restricted environments, reinforcing the system’s
grounding in low-level performance telemetry.
The declared functions define a disciplined lifecycle for configuration handling: setting
sane defaults, loading from a file, overriding via command-line arguments, and dumping
the active configuration state. This layered approach (defaults → file → CLI overrides)
aligns with best practices in Unix-style tooling and ensures predictable behavior across
deployment scenarios. Overall, this header represents a well-architected configuration
interface that balances safety, extensibility, and operational transparency, forming a stable
foundation for a performance monitoring and anomaly detection system intended to
operate reliably in diverse runtime environments.
*/

#ifndef CPUGUARD_CONFIG_H
#define CPUGUARD_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define CONFIG_MAX_PATH 256
#define CONFIG_MAX_LINE 512

typedef struct {
    uint32_t sampling_interval_us;
    uint32_t learning_duration_sec;
    double   z_threshold;
    uint32_t burst_window;
    uint32_t ringbuffer_capacity;
    int      target_cpu;
    pid_t    target_pid;
    char     log_file[CONFIG_MAX_PATH];
    bool     log_to_file;
    bool     log_to_syslog;
    bool     verbose;
    bool     per_process_mode;
    double   risk_decay_factor;
    uint32_t correlation_window_sec;
    uint32_t alert_cooldown_sec;
    bool     pmu_test;
    char     socket_path[CONFIG_MAX_PATH];
    bool     enable_ml_output;
} guardian_config_t;


void config_set_defaults(guardian_config_t *cfg);


int config_load_file(guardian_config_t *cfg, const char *path);


int config_parse_args(guardian_config_t *cfg, int argc, char *argv[]);


void config_dump(const guardian_config_t *cfg);

#endif 
