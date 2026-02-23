/*This synthetic workload generator is a deliberately engineered testing tool designed to 
validate CPU Guardian’s detection capabilities under controlled but realistic stress 
scenarios. Rather than being a simple CPU burner, it carefully crafts execution patterns 
that target specific microarchitectural behaviors—cache usage, branch prediction accuracy, 
and mixed-channel stress—so that PMU-based telemetry can be meaningfully evaluated.
The program supports four operational modes, each representing a different behavioral profile. 
Mode 1 establishes a clean baseline: sequential memory access over a modest array and 
highly predictable branches. Because the branch condition (`arr[i] > 0`) is always true 
and memory is accessed linearly, this workload produces low branch misprediction rates 
and minimal cache disruption. It serves as a statistical reference for “normal” execution 
characteristics.
Mode 2 intentionally stresses the cache hierarchy. By allocating a large 64 MB memory region 
and performing pseudo-random accesses using a xorshift PRNG, it defeats spatial and temporal 
locality. This mimics Prime+Probe or cache pollution behaviors where large working sets and random 
indexing cause elevated cache miss rates. The repeated random probing generates measurable pressure 
on last-level cache (LLC), making it ideal for validating cache-miss-based anomaly detection.
Mode 3 shifts focus to the branch predictor. It fills memory with pseudo-random values and 
executes deeply nested conditional logic with multiple thresholds. Because branch outcomes vary 
unpredictably, the CPU’s branch predictor cannot stabilize, resulting in elevated branch misprediction 
counts. This directly exercises the PMU’s branch-related counters and tests whether IPC degradation 
and branch miss spikes are detected correctly.
Mode 4 combines both stress patterns in alternating bursts, simulating a more realistic attacker 
who probes multiple microarchitectural channels. By switching between cache thrashing and branch-heavy 
logic phases, it produces fluctuating telemetry signatures rather than a steady abnormal state. 
This is particularly useful for evaluating temporal anomaly detection models that must handle dynamic 
patterns.
The design also includes practical safeguards. A volatile `running` flag controlled by signal 
handlers allows graceful termination via SIGINT or SIGTERM. The `sum` variable prevents compiler 
optimization from eliminating workload loops, ensuring counters reflect actual execution. Duration-based 
execution provides deterministic test windows for repeatable benchmarking.
Overall, this program is not just a stress tool—it is a structured microarchitectural behavior simulator. 
It enables systematic validation of telemetry accuracy, counter scaling, anomaly thresholds, and ML model 
responsiveness under controlled yet adversarial-like CPU conditions.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>



static volatile sig_atomic_t running = 1;

static void handler(int sig)
{
    (void)sig;
    running = 0;
}


static void workload_normal(int duration)
{
    printf("[workload] Normal baseline: sequential access, predictable branches\n");

    const size_t SIZE = 1024 * 1024;
    int *arr = malloc(SIZE * sizeof(int));
    if (!arr) { perror("malloc"); return; }

    for (size_t i = 0; i < SIZE; i++) arr[i] = (int)i;

    time_t end = time(NULL) + duration;
    uint64_t sum = 0;

    while (running && time(NULL) < end) {
        for (size_t i = 0; i < SIZE; i++) {
            sum += (uint64_t)arr[i];
            if (arr[i] > 0) sum++;  
        }
    }

    printf("[workload] sum=%lu (prevent optimisation)\n", (unsigned long)sum);
    free(arr);
}


static void workload_cache_stress(int duration)
{
    printf("[workload] Cache stress: random access across 64 MB\n");

    const size_t SIZE = 16 * 1024 * 1024;   
    int *arr = malloc(SIZE * sizeof(int));
    if (!arr) { perror("malloc"); return; }

    for (size_t i = 0; i < SIZE; i++) arr[i] = (int)i;


    uint64_t state = 0xDEADBEEFCAFEBABEULL;
    time_t end = time(NULL) + duration;
    uint64_t sum = 0;

    while (running && time(NULL) < end) {
        for (int i = 0; i < 100000; i++) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            size_t idx = (size_t)(state % SIZE);
            sum += (uint64_t)arr[idx];
        }
    }

    printf("[workload] sum=%lu (prevent optimisation)\n", (unsigned long)sum);
    free(arr);
}


static void workload_branch_stress(int duration)
{
    printf("[workload] Branch stress: unpredictable conditional branches\n");

    const size_t SIZE = 1024 * 1024;
    int *arr = malloc(SIZE * sizeof(int));
    if (!arr) { perror("malloc"); return; }

    
    uint64_t state = 0x12345678ABCDEF01ULL;
    for (size_t i = 0; i < SIZE; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        arr[i] = (int)(state & 0xFF);
    }

    time_t end = time(NULL) + duration;
    uint64_t sum = 0;

    while (running && time(NULL) < end) {
        for (size_t i = 0; i < SIZE; i++) {
            
            if (arr[i] > 128) {
                sum += (uint64_t)arr[i] * 3;
            } else if (arr[i] > 64) {
                sum -= (uint64_t)arr[i];
            } else if (arr[i] > 32) {
                sum ^= (uint64_t)arr[i];
            } else {
                sum += 1;
            }
        }
    }

    printf("[workload] sum=%lu (prevent optimisation)\n", (unsigned long)sum);
    free(arr);
}


static void workload_mixed(int duration)
{
    printf("[workload] Mixed pattern: alternating cache+branch bursts\n");

    const size_t SIZE = 8 * 1024 * 1024;
    int *arr = malloc(SIZE * sizeof(int));
    if (!arr) { perror("malloc"); return; }

    uint64_t state = 0xAAAABBBBCCCCDDDDULL;
    for (size_t i = 0; i < SIZE; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        arr[i] = (int)(state & 0xFFFF);
    }

    time_t end = time(NULL) + duration;
    uint64_t sum = 0;
    int phase = 0;

    while (running && time(NULL) < end) {
        if (phase % 2 == 0) {
        
            for (int i = 0; i < 200000; i++) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                sum += (uint64_t)arr[state % SIZE];
            }
        } else {
        
            for (size_t i = 0; i < SIZE && i < 500000; i++) {
                if (arr[i] > 32768)      sum += (uint64_t)arr[i];
                else if (arr[i] > 16384) sum -= (uint64_t)arr[i];
                else if (arr[i] > 8192)  sum ^= (uint64_t)arr[i];
                else                      sum += 1;
            }
        }
        phase++;
    }

    printf("[workload] sum=%lu phases=%d (prevent optimisation)\n",
           (unsigned long)sum, phase);
    free(arr);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <mode> [duration_sec]\n"
            "  mode 1: Normal baseline\n"
            "  mode 2: Cache stress (Prime+Probe simulation)\n"
            "  mode 3: Branch misprediction stress\n"
            "  mode 4: Mixed attack pattern\n",
            argv[0]);
        return 1;
    }

    int mode = atoi(argv[1]);
    int duration = (argc >= 3) ? atoi(argv[2]) : 30;

    signal(SIGINT, handler);
    signal(SIGTERM, handler);

    printf("=== CPU Guardian Synthetic Workload ===\n");
    printf("PID: %d  Mode: %d  Duration: %d sec\n\n",
           getpid(), mode, duration);

    switch (mode) {
    case 1: workload_normal(duration);       break;
    case 2: workload_cache_stress(duration); break;
    case 3: workload_branch_stress(duration); break;
    case 4: workload_mixed(duration);        break;
    default:
        fprintf(stderr, "Unknown mode %d\n", mode);
        return 1;
    }

    printf("\n[workload] done.\n");
    return 0;
}
