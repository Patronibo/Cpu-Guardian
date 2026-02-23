/*This module implements a process-level correlation engine that aggregates anomaly
scores over time and across samples, effectively transforming raw per-sample anomaly
signals into a higher-level, temporally aware risk model for each tracked process.
Architecturally, it acts as a stateful layer on top of the statistical anomaly detector,
maintaining per-PID risk entries and applying smoothing and decay logic to avoid reacting
to short-lived noise. The correlation_init function establishes a clean starting state by
zeroing the entire engine structure and assigning the configurable decay_factor and
window_sec, reinforcing deterministic initialization and eliminating the possibility of stale
state influencing risk calculations. This design choice is particularly important in long-
running monitoring daemons where memory reuse without proper reset could produce
misleading risk accumulation.
The internal find_or_create helper encapsulates the lifecycle management of tracked
processes. It first searches for an active entry matching the given PID, which ensures O(n)
lookup in a bounded array—acceptable given a fixed maximum (CORR_MAX_TRACKED). If no
active match is found, it attempts to reuse an inactive slot before allocating a new one,
demonstrating conscious memory discipline and avoidance of dynamic allocation, which is
appropriate in low-level monitoring systems where heap fragmentation or allocation
failure must be minimized. The explicit check against CORR_MAX_TRACKED enforces a hard
upper bound on tracked processes, preventing unbounded growth and maintaining
predictable memory usage. The call to correlation_resolve_comm upon entry creation
enriches each risk record with the process name retrieved from /proc/<pid>/comm, which
improves observability and diagnostic clarity without coupling risk tracking directly to
external logging systems.
The correlation_update function is where risk aggregation occurs. Each new anomaly
score is incorporated using an exponential moving average with a fixed smoothing factor
(alpha = 0.3), which balances responsiveness and stability: new spikes influence the score
significantly, but historical context still matters. This smoothing prevents abrupt oscillations
in risk level, which is critical when feeding alerting or mitigation systems. The function also
increments counters such as total_samples and suspicious_samples, providing
longitudinal metadata that could later support threshold-based escalation or reporting.
The use of timestamps (timestamp_ns) ensures that the system remains time-aware,
enabling subsequent decay logic to evaluate staleness accurately.
The correlation_decay function enforces temporal relevance by periodically attenuating
anomaly scores using the configured decay_factor and deactivating entries that have not
been observed within the configured time window. Converting window_sec to
nanoseconds reflects careful unit consistency and avoids subtle time calculation errors. The
decay mechanism models risk as a fading signal: unless reinforced by new anomalous
behavior, a process gradually returns to a neutral state. Setting very small scores explicitly
to zero prevents floating-point drift and maintains numerical cleanliness over long
runtimes. The correlation_lookup and correlation_top_risk functions provide efficient
read-only access to tracked entries, enabling external components to query per-process
risk or identify the most suspicious active process at any given moment—useful for
dashboards or automated mitigation triggers.
Finally, correlation_resolve_comm integrates system-level introspection by reading the
process name from the /proc filesystem. The function defensively handles invalid PIDs
and file access failures, defaulting to "<unknown>" when necessary. It carefully strips
trailing newlines from the comm string to ensure clean output formatting. Overall, this
module demonstrates disciplined systems programming: bounded memory usage,
avoidance of heap churn, temporal smoothing through exponential weighting, decay-
based lifecycle control, and integration with Linux process metadata. It effectively elevates
individual anomaly detections into a coherent, process-centric risk model suitable for real-
time performance monitoring or security anomaly correlation in a production-grade
monitoring agent.
*/

#include "correlation.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void correlation_init(correlation_engine_t *eng,
                      double decay_factor,
                      uint32_t window_sec)
{
    if (!eng) return;
    memset(eng, 0, sizeof(*eng));
    eng->decay_factor = decay_factor;
    eng->window_sec   = window_sec;
}

static process_risk_t *find_or_create(correlation_engine_t *eng,
                                       pid_t pid, pid_t tid)
{
    for (size_t i = 0; i < eng->count; i++) {
        if (eng->entries[i].pid == pid && eng->entries[i].active)
            return &eng->entries[i];
    }

    
    for (size_t i = 0; i < eng->count; i++) {
        if (!eng->entries[i].active) {
            memset(&eng->entries[i], 0, sizeof(eng->entries[i]));
            eng->entries[i].pid    = pid;
            eng->entries[i].tid    = tid;
            eng->entries[i].active = true;
            correlation_resolve_comm(&eng->entries[i]);
            return &eng->entries[i];
        }
    }

    if (eng->count >= CORR_MAX_TRACKED) return NULL;

    process_risk_t *entry = &eng->entries[eng->count++];
    memset(entry, 0, sizeof(*entry));
    entry->pid    = pid;
    entry->tid    = tid;
    entry->active = true;
    correlation_resolve_comm(entry);
    return entry;
}

void correlation_update(correlation_engine_t *eng,
                        pid_t pid, pid_t tid,
                        float score, uint64_t timestamp_ns)
{
    if (!eng) return;

    process_risk_t *entry = find_or_create(eng, pid, tid);
    if (!entry) return;

    entry->total_samples++;
    entry->last_seen_ns = timestamp_ns;

    
    float alpha = 0.3f;
    entry->anomaly_score = alpha * score + (1.0f - alpha) * entry->anomaly_score;

    if (score > 0.5f) {
        entry->suspicious_samples++;
    }
}

void correlation_decay(correlation_engine_t *eng, uint64_t now_ns)
{
    if (!eng) return;

    uint64_t window_ns = (uint64_t)eng->window_sec * 1000000000ULL;

    for (size_t i = 0; i < eng->count; i++) {
        process_risk_t *e = &eng->entries[i];
        if (!e->active) continue;

        uint64_t age = now_ns - e->last_seen_ns;
        if (age > window_ns) {
            e->active = false;
            continue;
        }

        e->anomaly_score *= (float)eng->decay_factor;
        if (e->anomaly_score < 0.001f) {
            e->anomaly_score = 0.0f;
        }
    }
}

const process_risk_t *correlation_lookup(const correlation_engine_t *eng,
                                          pid_t pid)
{
    if (!eng) return NULL;
    for (size_t i = 0; i < eng->count; i++) {
        if (eng->entries[i].pid == pid && eng->entries[i].active)
            return &eng->entries[i];
    }
    return NULL;
}

const process_risk_t *correlation_top_risk(const correlation_engine_t *eng)
{
    if (!eng || eng->count == 0) return NULL;

    const process_risk_t *best = NULL;
    for (size_t i = 0; i < eng->count; i++) {
        if (!eng->entries[i].active) continue;
        if (!best || eng->entries[i].anomaly_score > best->anomaly_score)
            best = &eng->entries[i];
    }
    return best;
}

void correlation_resolve_comm(process_risk_t *entry)
{
    if (!entry || entry->pid <= 0) {
        strncpy(entry->comm, "<unknown>", sizeof(entry->comm) - 1);
        return;
    }

    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/comm", entry->pid);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        strncpy(entry->comm, "<unknown>", sizeof(entry->comm) - 1);
        return;
    }

    if (!fgets(entry->comm, (int)sizeof(entry->comm), fp)) {
        strncpy(entry->comm, "<unknown>", sizeof(entry->comm) - 1);
    } else {
        /* Strip trailing newline */
        size_t len = strlen(entry->comm);
        if (len > 0 && entry->comm[len - 1] == '\n')
            entry->comm[len - 1] = '\0';
    }

    fclose(fp);
}
