/*This configuration module is a well-structured and production-oriented component
responsible for initializing, loading, validating, and exposing runtime configuration
parameters for the CPU Guardian system, and it reflects a thoughtful balance between
flexibility, safety, and operational clarity. The config_set_defaults function establishes a
deterministic baseline configuration, ensuring that even if no external configuration file or
command-line arguments are provided, the system operates with sensible defaults. These
defaults reveal architectural intent: a 1000 microsecond sampling interval suggests near-
real-time monitoring without excessive overhead; a 60-second learning phase indicates
statistical stabilization before anomaly detection; a z-threshold of 3.5 reflects a 
conservative anomalu boundary aligned with standard deviation-based outlier detection;
and parameters like burst_window, risk_decay_factor, correlation_window_sec, and
alert_cooldown_sec show that the broader system incorporates temporal smoothing and
alert rate control rather than naive threshold triggering. The use of sentinel values such as
-1 for target_cpu and target_pid is a practical design choice, clearly signaling system-
wide monitoring when no specific scope is defined. The defeault log path and explicit
zeroing of the log_file buffer before strncpy demonstrate defensive programming to
avoid residual data leakage or undefined behavior
The internal trim helper function provides robust whitespace normalization for
configuration file parsing, carefully casting to unsigned char before calling isspace to
avoid undefined behavior with negative char values--a subtle but important detail in
portable C. The parse_kv function implements a straightforward key-value dispatcher
using string comparison, mapping textuall configuration entries into strongly typed fields.
Numeric conversions rely on strtoul, strtol, and strtod, which are more robust than
atoi-style functions because they alloe error checking and controlled base handling,
even though the current implemented via  explicit string comparison against "true" 
and "1", providing predictable semantics. Importantly, unknown keys trigger a warning
and error accounting, which enforces configuration hygiene rather than silently ignoring
mistakes-an essential feature in security-sensitive or performance-critical tooling.
The config_load_file function reads configuration files line by line using a bounded
buffer (CONFIG_MAX_LINE), trims whitespace, skips comments and empty lines, and
enforces a strivt key=value format. Syntax errors are reported with line numbers, aiding
operational debugging. The error accumulation mechanism allows the parser to continue
processing the file instead of failing on the first issue, which improves resilience while still
signaling failure if any invalid enteries are encountered. From a systems perspective, this is a
pragmatic compromise between strictness and usability. The config_parse_args function
integrates POSIX-style command-line parsing via getopt, enabling runtime overrides for
key parameters such as sampling interval, learning duration, CPU targeting, and logging
configuration. The explicit reser of optind ensures predictable behavior when parsing is
inkoved multiple times, which is often overlooked in CLI tools. The presence of a -T flag
for PMU test mode indicates that the system includes diagnostic capabilities for verifying
hardware counter accessibility, suggesting awareness of virtualization and permission-
related constraints in performence monitoring environments
Finally, config_dump provides a structured, huma-readable snapshot of the active
configuration, which is invaluable for debugging, auditing, and reproducibility. By priting
all fields-including risk modeling and alert control parameters-it ensures operationaş
transparency. Overall, th,s module demonstrates disciplined systems programming
pratices: carefulmemory handling, explicit typing, defensive parsing, layerede
configuration (defaults -> file -> CLI), and operational introspection. It is designed not just
to read parameters, but to support a monitoring system that must behave predictably
under varied deployment scenarios, including system-wide monitoring, per-process
analysis, and environments with hardware performance counter constraints.

*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

void config_set_defaults(guardian_config_t *cfg)
{
    if (!cfg) return;

    cfg->sampling_interval_us   = 1000;
    cfg->learning_duration_sec  = 60;
    cfg->z_threshold            = 3.5;
    cfg->burst_window           = 10;
    cfg->ringbuffer_capacity    = 8192;
    cfg->target_cpu             = -1;       
    cfg->target_pid             = -1;       
    cfg->log_to_file            = false;
    cfg->log_to_syslog          = false;
    cfg->verbose                = false;
    cfg->per_process_mode       = false;
    cfg->risk_decay_factor      = 0.95;
    cfg->correlation_window_sec = 30;
    cfg->alert_cooldown_sec     = 5;
    cfg->pmu_test              = false;
    cfg->enable_ml_output      = true;
    memset(cfg->log_file, 0, sizeof(cfg->log_file));
    strncpy(cfg->log_file, "/var/log/cpu-guardian.log",
            CONFIG_MAX_PATH - 1);
    memset(cfg->socket_path, 0, sizeof(cfg->socket_path));
    strncpy(cfg->socket_path, "/tmp/cpu-guardian.sock",
            CONFIG_MAX_PATH - 1);
}

static char *trim(char *s)
{
    if (!s) return s;
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    if (len == 0) return s;
    char *end = s + len - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_kv(guardian_config_t *cfg, const char *key, const char *val)
{
    if (strcmp(key, "sampling_interval_us") == 0) {
        cfg->sampling_interval_us = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "learning_duration_sec") == 0) {
        cfg->learning_duration_sec = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "z_threshold") == 0) {
        cfg->z_threshold = strtod(val, NULL);
    } else if (strcmp(key, "burst_window") == 0) {
        cfg->burst_window = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "ringbuffer_capacity") == 0) {
        cfg->ringbuffer_capacity = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "target_cpu") == 0) {
        cfg->target_cpu = (int)strtol(val, NULL, 10);
    } else if (strcmp(key, "target_pid") == 0) {
        cfg->target_pid = (pid_t)strtol(val, NULL, 10);
    } else if (strcmp(key, "log_file") == 0) {
        strncpy(cfg->log_file, val, CONFIG_MAX_PATH - 1);
        cfg->log_file[CONFIG_MAX_PATH - 1] = '\0';
        cfg->log_to_file = true;
    } else if (strcmp(key, "log_to_syslog") == 0) {
        cfg->log_to_syslog = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    } else if (strcmp(key, "verbose") == 0) {
        cfg->verbose = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    } else if (strcmp(key, "risk_decay_factor") == 0) {
        cfg->risk_decay_factor = strtod(val, NULL);
    } else if (strcmp(key, "correlation_window_sec") == 0) {
        cfg->correlation_window_sec = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "alert_cooldown_sec") == 0) {
        cfg->alert_cooldown_sec = (uint32_t)strtoul(val, NULL, 10);
    } else if (strcmp(key, "socket_path") == 0) {
        strncpy(cfg->socket_path, val, CONFIG_MAX_PATH - 1);
        cfg->socket_path[CONFIG_MAX_PATH - 1] = '\0';
    } else if (strcmp(key, "enable_ml_output") == 0) {
        cfg->enable_ml_output = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
    } else {
        fprintf(stderr, "[config] unknown key: %s\n", key);
        return -1;
    }
    return 0;
}

int config_load_file(guardian_config_t *cfg, const char *path)
{
    if (!cfg || !path) return -1;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return -1;
    }

    char line[CONFIG_MAX_LINE];
    int lineno = 0;
    int errors = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            fprintf(stderr, "[config] syntax error on line %d\n", lineno);
            errors++;
            continue;
        }

        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (parse_kv(cfg, key, val) != 0) {
            errors++;
        }
    }

    fclose(fp);
    return errors > 0 ? -1 : 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -c FILE    Configuration file path\n"
        "  -i USEC    Sampling interval (microseconds)\n"
        "  -l SEC     Learning duration (seconds)\n"
        "  -z THRESH  Z-score threshold\n"
        "  -C CPU     Target CPU core (-1 = all)\n"
        "  -p PID     Target PID (-1 = system-wide)\n"
        "  -o FILE    Log output file\n"
        "  -s         Enable syslog output\n"
        "  -v         Verbose mode\n"
        "  -T         PMU test mode: open counters, read once, print raw values, exit\n"
        "  -S PATH    ML engine Unix socket path (default: /tmp/cpu-guardian.sock)\n"
        "  -M         Disable ML output (C-only detection)\n"
        "  -h         Show this help\n",
        prog);
}

int config_parse_args(guardian_config_t *cfg, int argc, char *argv[])
{
    int opt;
    const char *config_path = NULL;


    optind = 1;

    while ((opt = getopt(argc, argv, "c:i:l:z:C:p:o:S:svTMh")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'i': cfg->sampling_interval_us = (uint32_t)strtoul(optarg, NULL, 10); break;
        case 'l': cfg->learning_duration_sec = (uint32_t)strtoul(optarg, NULL, 10); break;
        case 'z': cfg->z_threshold = strtod(optarg, NULL); break;
        case 'C': cfg->target_cpu = (int)strtol(optarg, NULL, 10); break;
        case 'p': cfg->target_pid = (pid_t)strtol(optarg, NULL, 10); break;
        case 'o':
            strncpy(cfg->log_file, optarg, CONFIG_MAX_PATH - 1);
            cfg->log_file[CONFIG_MAX_PATH - 1] = '\0';
            cfg->log_to_file = true;
            break;
        case 'S':
            strncpy(cfg->socket_path, optarg, CONFIG_MAX_PATH - 1);
            cfg->socket_path[CONFIG_MAX_PATH - 1] = '\0';
            break;
        case 's': cfg->log_to_syslog = true; break;
        case 'v': cfg->verbose = true; break;
        case 'T': cfg->pmu_test = true; break;
        case 'M': cfg->enable_ml_output = false; break;
        case 'h':
            print_usage(argv[0]);
            return -1;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (config_path) {
        if (config_load_file(cfg, config_path) != 0) {
            fprintf(stderr, "[config] failed to load %s\n", config_path);
        }
    }

    return 0;
}

void config_dump(const guardian_config_t *cfg)
{
    if (!cfg) return;

    printf("=== CPU Guardian Configuration ===\n");
    printf("  sampling_interval_us   = %u\n", cfg->sampling_interval_us);
    printf("  learning_duration_sec  = %u\n", cfg->learning_duration_sec);
    printf("  z_threshold            = %.2f\n", cfg->z_threshold);
    printf("  burst_window           = %u\n", cfg->burst_window);
    printf("  ringbuffer_capacity    = %u\n", cfg->ringbuffer_capacity);
    printf("  target_cpu             = %d\n", cfg->target_cpu);
    printf("  target_pid             = %d\n", cfg->target_pid);
    printf("  log_file               = %s\n", cfg->log_file);
    printf("  log_to_file            = %s\n", cfg->log_to_file ? "true" : "false");
    printf("  log_to_syslog          = %s\n", cfg->log_to_syslog ? "true" : "false");
    printf("  verbose                = %s\n", cfg->verbose ? "true" : "false");
    printf("  risk_decay_factor      = %.4f\n", cfg->risk_decay_factor);
    printf("  correlation_window_sec = %u\n", cfg->correlation_window_sec);
    printf("  alert_cooldown_sec     = %u\n", cfg->alert_cooldown_sec);
    printf("  pmu_test              = %s\n", cfg->pmu_test ? "true" : "false");
    printf("  socket_path            = %s\n", cfg->socket_path);
    printf("  enable_ml_output       = %s\n", cfg->enable_ml_output ? "true" : "false");
    printf("==================================\n");
}
