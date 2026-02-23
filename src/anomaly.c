/*
This code implements a lightweight yet thoughtfully designed statistical anomaly
detection engine built around low-level telemetry metrics, and its structure clearly reflects
a two-phase architecture: a learning phase to establish a behavioral baseline and a 
detection phase to ecaluate incoming samples againts that baseline. The anomaşy_init
function carefully initializes the engine by first validating the input pointer and then
zeroing the entire structure using memset, which is important to avaid undefined behavior
from uninitialized accumulators such as the running sums and squared sums. it allocates a
circular buffer (recent_cmr) sized according to burst_window using calloc, ensuring
both memory allocation and zero-initialization in one step, which contributes to
deterministic behavior in later oscillation analysis. The learning phase, implemented in
anomaly_learn, incrementallu accumulates the sum and squared sum of cache miss rate,
branch miss rate, and IPC values, enabling a single-pass computation of variance using the
classical identity E[x²] − (E[x])². This approach is memory-efficient and well-suited for
streaming telemetry, as it avoids storing historical samplse. In
anomaly_finalize_baseline, the code computes the mean and variance for each metric,
applying defensive programming practices by clamping negative variance values (which
may arise from floating-point rounding errors) to zero before taking the square root; this
reflects an awareness of numerical stability issues. The helper compute_z function further
reinforces robustness by returning zero when the standart deviation is extremely small
(below 1e-12), preventing division-by-zero or artificially inflated z-scores.
The detection logic in anomaly_detect is where the system's desing becomes particularly
interesting. Each new telemtry sample is normalized into a z-score relative to the
computed baseline, and anomaly flags are set based on threshold comparions. The
asymmetry in checks--positive spikes for cache and branch miss rates, but negative
deviation for IPC--demonstrates domain awareness, since IPC degradation typically signals
pipeline consecutive anomalies to identify burst patterns, effectively distinguishing sustained
abnormal behavior from transient noise. Additionally, the circular buffer is continuously
updated and passed to detect_oscillation, which analyzes directional changes across
recent samples to detect high-frequency oscillatory patterns; this is especially relevant for
identifying instability phenomena such as cache thrashing or scheduler-induced jitter. The
composite score calculation introduces a smooth, bounded severity metric using a
sigmoid-like transformation of the maximum absolute z-score, ensuring the result remains
within [0,1] and scales non-linearly with deviation magnitude, which is useful for
downstream alerting or scoring systems.
From a systems programming perspective, the implementation demonstrates careful
memory management and low algorithmic complexity (O(1) per sample), making it
suitable for real-time monitoring contexts. The use of a thread-local static buffer in
anomaly_flags_str avoids data races in multithreaded scenarios while keeping the
interface simple, though it remains limited by its fixed buffer size. Overall, the design
balances statistical rigor, computational efficiency, and practical robustness, forming a
solid foundation for a performance anomaly detection module that could realistically be
integrated into low-level telemetry pipelines or performance monitoring tools in
production environments.
*/ 

#include "anomaly.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int anomaly_init(anomaly_engine_t *eng, double z_threshold, uint32_t burst_window)
{
    if (!eng) return -1;
    memset(eng, 0, sizeof(*eng));

    eng->z_threshold  = z_threshold;
    eng->burst_window = burst_window;

    eng->recent_cap = burst_window;
    eng->recent_cmr = calloc(eng->recent_cap, sizeof(float));
    if (!eng->recent_cmr) return -1;

    return 0;
}

void anomaly_destroy(anomaly_engine_t *eng)
{
    if (!eng) return;
    free(eng->recent_cmr);
    eng->recent_cmr = NULL;
}

void anomaly_learn(anomaly_engine_t *eng, const telemetry_sample_t *s)
{
    if (!eng || !s) return;

    double cmr = (double)s->cache_miss_rate;
    double bmr = (double)s->branch_miss_rate;
    double ipc = (double)s->ipc;

    eng->sum_cmr  += cmr;
    eng->sum_cmr2 += cmr * cmr;
    eng->sum_bmr  += bmr;
    eng->sum_bmr2 += bmr * bmr;
    eng->sum_ipc  += ipc;
    eng->sum_ipc2 += ipc * ipc;
    eng->n++;
}

void anomaly_finalize_baseline(anomaly_engine_t *eng)
{
    if (!eng || eng->n < 1) return;

    double n = (double)eng->n;

    eng->baseline.mean_cache_miss_rate  = eng->sum_cmr / n;
    eng->baseline.mean_branch_miss_rate = eng->sum_bmr / n;
    eng->baseline.mean_ipc              = eng->sum_ipc / n;

    
    double var_cmr = 0.0, var_bmr = 0.0, var_ipc = 0.0;
    if (eng->n >= 2) {
        var_cmr = (eng->sum_cmr2 / n)
                - (eng->baseline.mean_cache_miss_rate
                   * eng->baseline.mean_cache_miss_rate);
        var_bmr = (eng->sum_bmr2 / n)
                - (eng->baseline.mean_branch_miss_rate
                   * eng->baseline.mean_branch_miss_rate);
        var_ipc = (eng->sum_ipc2 / n)
                - (eng->baseline.mean_ipc * eng->baseline.mean_ipc);
        if (var_cmr < 0.0) var_cmr = 0.0;
        if (var_bmr < 0.0) var_bmr = 0.0;
        if (var_ipc < 0.0) var_ipc = 0.0;
    }

    eng->baseline.std_cache_miss_rate  = sqrt(var_cmr);
    eng->baseline.std_branch_miss_rate = sqrt(var_bmr);
    eng->baseline.std_ipc              = sqrt(var_ipc);

    eng->baseline.sample_count = eng->n;
    eng->baseline.ready        = true;

    fprintf(stderr, "[anomaly] baseline computed from %zu samples\n", eng->n);
    fprintf(stderr, "  cache_miss_rate  mean=%.6f std=%.6f\n",
            eng->baseline.mean_cache_miss_rate,
            eng->baseline.std_cache_miss_rate);
    fprintf(stderr, "  branch_miss_rate mean=%.6f std=%.6f\n",
            eng->baseline.mean_branch_miss_rate,
            eng->baseline.std_branch_miss_rate);
    fprintf(stderr, "  ipc              mean=%.6f std=%.6f\n",
            eng->baseline.mean_ipc,
            eng->baseline.std_ipc);
}

static double compute_z(double value, double mean, double std)
{
    if (std < 1e-12) return 0.0;
    return (value - mean) / std;
}


static bool detect_oscillation(const float *buf, size_t cap, size_t idx)
{
    if (cap < 4) return false;

    int direction_changes = 0;
    int prev_dir = 0;

    for (size_t i = 1; i < cap; i++) {
        size_t a = (idx + cap - i)     % cap;
        size_t b = (idx + cap - i - 1) % cap;
        float diff = buf[a] - buf[b];
        int dir = (diff > 0.0f) ? 1 : ((diff < 0.0f) ? -1 : 0);
        if (dir != 0 && dir != prev_dir && prev_dir != 0)
            direction_changes++;
        if (dir != 0) prev_dir = dir;
    }

    return direction_changes >= (int)(cap / 2);
}

void anomaly_detect(anomaly_engine_t *eng,
                    const telemetry_sample_t *s,
                    anomaly_result_t *result)
{
    if (!eng || !s || !result) return;
    memset(result, 0, sizeof(*result));

    if (!eng->baseline.ready) return;

    double cmr = (double)s->cache_miss_rate;
    double bmr = (double)s->branch_miss_rate;
    double ipc = (double)s->ipc;

    result->z_cache_miss  = compute_z(cmr, eng->baseline.mean_cache_miss_rate,
                                       eng->baseline.std_cache_miss_rate);
    result->z_branch_miss = compute_z(bmr, eng->baseline.mean_branch_miss_rate,
                                       eng->baseline.std_branch_miss_rate);
    result->z_ipc         = compute_z(ipc, eng->baseline.mean_ipc,
                                       eng->baseline.std_ipc);

    bool anomalous = false;

    if (result->z_cache_miss > eng->z_threshold) {
        result->anomaly_flags |= ANOMALY_CACHE_MISS_SPIKE;
        anomalous = true;
    }

   
    if (result->z_branch_miss > eng->z_threshold) {
        result->anomaly_flags |= ANOMALY_BRANCH_MISS_SPIKE;
        anomalous = true;
    }

    
    if (result->z_ipc < -eng->z_threshold) {
        result->anomaly_flags |= ANOMALY_IPC_COLLAPSE;
        anomalous = true;
    }

    
    eng->recent_cmr[eng->recent_idx] = (float)cmr;
    eng->recent_idx = (eng->recent_idx + 1) % eng->recent_cap;

   
    if (anomalous) {
        eng->consecutive_anomalies++;
        if (eng->consecutive_anomalies >= eng->burst_window) {
            result->anomaly_flags |= ANOMALY_BURST_PATTERN;
        }
    } else {
        eng->consecutive_anomalies = 0;
    }
    result->sustained_count = eng->consecutive_anomalies;

    
    if (detect_oscillation(eng->recent_cmr, eng->recent_cap, eng->recent_idx)) {
        result->anomaly_flags |= ANOMALY_OSCILLATION;
        anomalous = true;
    }

    
    double max_z = fabs(result->z_cache_miss);
    if (fabs(result->z_branch_miss) > max_z) max_z = fabs(result->z_branch_miss);
    if (fabs(result->z_ipc)         > max_z) max_z = fabs(result->z_ipc);

    
    result->composite_score = 1.0 - 1.0 / (1.0 + max_z / eng->z_threshold);
    if (result->composite_score > 1.0) result->composite_score = 1.0;
    if (result->composite_score < 0.0) result->composite_score = 0.0;
}

const char *anomaly_flags_str(uint32_t flags)
{
    static __thread char buf[256];
    buf[0] = '\0';

    if (flags == 0) {
        snprintf(buf, sizeof(buf), "none");
        return buf;
    }

    if (flags & ANOMALY_CACHE_MISS_SPIKE)
        strncat(buf, "cache_miss_spike ", sizeof(buf) - strlen(buf) - 1);
    if (flags & ANOMALY_BRANCH_MISS_SPIKE)
        strncat(buf, "branch_miss_spike ", sizeof(buf) - strlen(buf) - 1);
    if (flags & ANOMALY_IPC_COLLAPSE)
        strncat(buf, "ipc_collapse ", sizeof(buf) - strlen(buf) - 1);
    if (flags & ANOMALY_BURST_PATTERN)
        strncat(buf, "burst_pattern ", sizeof(buf) - strlen(buf) - 1);
    if (flags & ANOMALY_OSCILLATION)
        strncat(buf, "oscillation ", sizeof(buf) - strlen(buf) - 1);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == ' ') buf[len - 1] = '\0';

    return buf;
}
