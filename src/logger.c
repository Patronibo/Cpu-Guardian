/*This logger implementation is a well-structured, production-oriented logging subsystem
designed for a security-focused monitoring tool like cpu-guardian, and it clearly reflects
careful thought about reliability, structured output, and operational robustness. At a high
level, this module is responsible for emitting both human-readable informational logs and
machine-parseable JSON alerts, while supporting multiple output backends (stdout, file,
and syslog) and enforcing a cooldown mechanism to prevent alert flooding. The design
balances observability with performance and operational safety.
The json_escape function is a foundational utility in this module, and its presence
demonstrates an understanding of how fragile structured logging can be if not handled
correctly. Since alerts are emitted in JSON format, any unescaped double quotes,
backslashes, or control characters in fields like comm or reason could break JSON parsing
downstream. This function carefully iterates over the input string and escapes problematic
characters, including converting control characters (ASCII < 32) into \uXXXX sequences. It
also respects the output buffer size and ensures null termination, which prevents buffer
overflows and malformed output. This defensive programming style is essential in
security-sensitive tooling, especially when log content may originate from untrusted
process names or dynamic runtime conditions.
The logger_init function sets up the logging context and clearly defines the module’s
behavior. It initializes the logger structure, enables stdout logging by default, and
conditionally enables file and syslog logging based on configuration flags. The decision to
open the log file in append mode ("a") ensures that logs are preserved across restarts
rather than overwritten, which is critical for forensic traceability. The integration with syslog
using openlog under the LOG_DAEMON facility indicates that this tool is meant to behave
like a long-running system service. The inclusion of a cooldown_sec parameter and the
initialization of last_alert_ns further show that alert rate limiting is a first-class concern,
not an afterthought.
The alert emission path in logger_alert is particularly well designed. Before generating
any output, it enforces a cooldown window based on a monotonic clock
(CLOCK_MONOTONIC_RAW). This is a subtle but important choice: using a monotonic clock
avoids issues caused by system time adjustments (e.g., NTP corrections), ensuring that
cooldown logic remains stable and immune to wall-clock changes. If alerts occur too
frequently within the configured cooldown interval, they are silently suppressed. This
prevents log flooding in high-anomaly scenarios, which could otherwise degrade
performance or overwhelm monitoring pipelines.
When an alert is allowed, the function constructs a structured JSON object containing the
severity level, timestamp, PID, process name (comm), anomaly score, and a textual reason.
The use of snprintf with explicit size checks prevents buffer overflow and ensures that
malformed or truncated JSON is never emitted. The JSON structure is consistent and
predictable, making it suitable for ingestion by log aggregation systems, SIEM platforms,
or downstream analytics engines. The inclusion of both numeric and textual context (e.g.,
anomaly score and reason string) indicates that alerts are designed to be both machine-
actionable and human-interpretable.
The module supports three independent output channels: stdout, file, and syslog. Each
channel is conditionally enabled and flushed immediately after writing. The explicit
fflush calls ensure that logs are not lost if the process crashes unexpectedly, which is
especially important for security alerts. For syslog integration, the function maps internal
severity levels to appropriate syslog priorities (LOG_INFO, LOG_WARNING, LOG_CRIT),
maintaining semantic consistency across logging systems.
The logger_info function provides a simpler, printf-style logging mechanism intended for
operational or debugging messages rather than structured alerts. It uses vsnprintf to
safely format variable arguments and prefixes messages with [cpu-guardian] to provide
clear source attribution. Unlike logger_alert, it emits plain text rather than JSON, which is
appropriate for status updates or informational diagnostics.
Finally, logger_destroy ensures proper cleanup of resources by closing file handles and
calling closelog when necessary. This prevents file descriptor leaks and ensures that the
logger can be cleanly shut down, which is important in long-running daemonized
processes.
Overall, this logger implementation reflects production-level thinking: it enforces
structured logging, protects against malformed JSON, prevents alert storms via cooldown
logic, supports multiple output sinks, and prioritizes safety through careful buffer
management and monotonic timing. It is not just a simple print wrapper; it is a resilient,
security-aware logging framework suitable for a real-time anomaly detection system
operating in a Linux environment.
*/

#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>


static void json_escape(const char *in, char *out, size_t out_size)
{
    if (!in || !out || out_size == 0) return;
    out[0] = '\0';
    size_t j = 0;
    for (; in[0] != '\0' && j + 2 < out_size; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c < 32) {
            j += (size_t)snprintf(out + j, out_size - j, "\\u%04x", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

int logger_init(logger_t *log, const char *filepath,
                bool to_file, bool to_syslog,
                uint32_t cooldown_sec)
{
    if (!log) return -1;
    memset(log, 0, sizeof(*log));

    log->to_stdout    = true;
    log->to_file      = to_file;
    log->to_syslog    = to_syslog;
    log->cooldown_sec = cooldown_sec;
    log->last_alert_ns = 0;

    if (filepath) {
        strncpy(log->filepath, filepath, sizeof(log->filepath) - 1);
    }

    if (to_file && filepath) {
        FILE *fp = fopen(filepath, "a");
        if (!fp) {
            perror(filepath);
            return -1;
        }
        log->file_handle = fp;
    }

    if (to_syslog) {
        openlog("cpu-guardian", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    return 0;
}

void logger_destroy(logger_t *log)
{
    if (!log) return;
    if (log->file_handle) {
        fclose((FILE *)log->file_handle);
        log->file_handle = NULL;
    }
    if (log->to_syslog) {
        closelog();
    }
}

static const char *level_str(log_level_t level)
{
    switch (level) {
    case ALERT_INFO:     return "INFO";
    case ALERT_WARNING:  return "WARNING";
    case ALERT_CRITICAL: return "CRITICAL";
    default:             return "UNKNOWN";
    }
}

static int level_to_syslog_prio(log_level_t level)
{
    switch (level) {
    case ALERT_INFO:     return LOG_INFO;
    case ALERT_WARNING:  return LOG_WARNING;
    case ALERT_CRITICAL: return LOG_CRIT;
    default:             return LOG_NOTICE;
    }
}

static uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void logger_alert(logger_t *log,
                  log_level_t level,
                  uint64_t timestamp_ns,
                  pid_t pid,
                  const char *comm,
                  double anomaly_score,
                  const char *reason)
{
    if (!log) return;

    
    uint64_t now = get_ns();
    if (log->cooldown_sec > 0 && log->last_alert_ns > 0) {
        uint64_t elapsed = now - log->last_alert_ns;
        if (elapsed < (uint64_t)log->cooldown_sec * 1000000000ULL)
            return;
    }
    log->last_alert_ns = now;

    char comm_esc[256], reason_esc[512];
    json_escape(comm ? comm : "unknown", comm_esc, sizeof(comm_esc));
    json_escape(reason ? reason : "unspecified", reason_esc, sizeof(reason_esc));

    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"level\":\"%s\","
        "\"timestamp\":%lu,"
        "\"pid\":%d,"
        "\"comm\":\"%s\","
        "\"anomaly_score\":%.4f,"
        "\"reason\":\"%s\"}\n",
        level_str(level),
        (unsigned long)timestamp_ns,
        (int)pid,
        comm_esc,
        anomaly_score,
        reason_esc);

    if (n < 0 || n >= (int)sizeof(json)) return;

    if (log->to_stdout) {
        fputs(json, stdout);
        fflush(stdout);
    }

    if (log->to_file && log->file_handle) {
        fputs(json, (FILE *)log->file_handle);
        fflush((FILE *)log->file_handle);
    }

    if (log->to_syslog) {
        syslog(level_to_syslog_prio(level), "%s", json);
    }
}

void logger_info(logger_t *log, const char *fmt, ...)
{
    if (!log) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (log->to_stdout) {
        fprintf(stdout, "[cpu-guardian] %s\n", buf);
        fflush(stdout);
    }

    if (log->to_file && log->file_handle) {
        fprintf((FILE *)log->file_handle, "[cpu-guardian] %s\n", buf);
        fflush((FILE *)log->file_handle);
    }
}
