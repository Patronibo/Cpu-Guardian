/*This header defines the public interface and configuration model for the cpu-guardian
logging subsystem, and it reflects a clean separation between structured alerting and
general informational output. At the top, the log_level_t enum formalizes three severity
levels—ALERT_INFO, ALERT_WARNING, and ALERT_CRITICAL—which establishes a clear
semantic contract for how alerts are categorized internally and mapped to external
systems like syslog. By encoding severity as an enum rather than raw integers, the design
improves readability, type safety, and long-term maintainability.
The logger_t structure encapsulates the runtime configuration and state of the logging
engine. It supports three independent output channels: stdout, file logging, and syslog
integration. The presence of boolean flags (to_stdout, to_file, to_syslog) allows
flexible deployment configurations without recompilation. The fixed-size filepath[256]
buffer avoids dynamic allocation while still supporting typical filesystem paths, reinforcing
predictable memory usage. The file_handle is stored as a void * (internally a FILE*),
which keeps the header lightweight and avoids forcing consumers to include <stdio.h>,
reducing header coupling. The inclusion of cooldown_sec and last_alert_ns reveals that
rate limiting is built directly into the logger’s state, enabling suppression of alert storms in
high-frequency anomaly conditions.
Function prototypes define a straightforward lifecycle. logger_init configures output
targets and cooldown behavior, while logger_destroy ensures proper cleanup of file
descriptors and syslog resources. The logger_alert function emits structured JSON alerts
containing severity, timestamp, process context, anomaly score, and a textual reason—
clearly designed for machine parsing by SIEM or log aggregation systems. In contrast,
logger_info provides a printf-style interface for human-readable operational messages.
The use of the __attribute__((format(printf, 2, 3))) annotation is a particularly
strong design choice: it enables compile-time format string checking, preventing common
bugs such as mismatched format specifiers and arguments.
Overall, this header defines a compact yet production-ready logging API that supports
structured security alerts, flexible output backends, and built-in rate limiting, all while
maintaining low coupling and predictable resource management suitable for a long-
running system daemon.
*/

#ifndef CPUGUARD_LOGGER_H
#define CPUGUARD_LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    ALERT_INFO     = 0,
    ALERT_WARNING  = 1,
    ALERT_CRITICAL = 2,
} log_level_t;

typedef struct {
    bool  to_stdout;
    bool  to_file;
    bool  to_syslog;
    char  filepath[256];
    void *file_handle;          
    uint32_t cooldown_sec;
    uint64_t last_alert_ns;
} logger_t;


int logger_init(logger_t *log, const char *filepath,
                bool to_file, bool to_syslog,
                uint32_t cooldown_sec);


void logger_destroy(logger_t *log);


void logger_alert(logger_t *log,
                  log_level_t level,
                  uint64_t timestamp_ns,
                  pid_t pid,
                  const char *comm,
                  double anomaly_score,
                  const char *reason);


void logger_info(logger_t *log, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif 
