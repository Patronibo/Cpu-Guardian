# CPU Guardian — Real-Time Side-Channel Attack Detection Engine

A production-grade, research-oriented defensive security engine written in pure C that detects potential CPU side-channel attacks in real time by analyzing microarchitectural behavior through hardware performance counters (PMU). Optional Python ML module (Isolation Forest + One-Class SVM) can run in parallel over a Unix socket for ensemble anomaly detection.

**This is NOT an exploit tool. This is a defensive runtime detection engine.**

Full ASCII version: **[PIPELINE.txt](PIPELINE.txt)**

---

## System Pipeline

```mermaid
flowchart TB
    subgraph CONFIG["CONFIGURATION"]
        CONF_FILE["guardian.conf\n(key=value)"]
        CLI["CLI Arguments\n-c -i -l -z -C -p -o -s -v -T -S -M"]
        DEFAULTS["Hard-coded Defaults\ninterval=1000µs, learning=60s\nz_threshold=3.5, burst=10\nringbuf=8192, decay=0.95"]
        CONF_FILE --> PARSE
        CLI --> PARSE
        DEFAULTS --> PARSE
        PARSE["config_set_defaults()\nconfig_parse_args()\nconfig_load_file()"]
    end

    PARSE --> CFG["guardian_config_t cfg"]
    CFG --> TEST_CHECK{"-T flag?"}
    TEST_CHECK -->|Yes| PMU_TEST["PMU Test Mode\npmu_open → pmu_read\nprint raw → exit"]
    TEST_CHECK -->|No| INIT

    subgraph INIT["SUBSYSTEM INITIALIZATION"]
        LOGGER_INIT["Logger Init\nstdout + file + syslog\ncooldown = 5s"]
        RB_INIT["Ring Buffer Init\nSPSC lock-free, 8192 slots\ncache-line aligned\natomic head/tail"]
        TEL_INIT["Telemetry Init\ntelemetry_start()\nspawns pthread"]
        ANOM_INIT["Anomaly Init\nz_threshold=3.5\nburst_window=10\nrecent_cmr[] buffer"]
        CORR_INIT["Correlation Init\ndecay=0.95, window=30s\ntracks up to 256 PIDs"]
        IPC_INIT["IPC Socket Init\n/tmp/cpu-guardian.sock\nSOCK_DGRAM, non-blocking"]
        LOGGER_INIT --> RB_INIT --> TEL_INIT
        TEL_INIT --> ANOM_INIT --> CORR_INIT --> IPC_INIT
    end

    CFG --> SIGNAL["Signal Setup\nSIGINT/SIGTERM\n→ g_shutdown = 1"]
```

```mermaid
flowchart TB
    subgraph PMU_THREAD["BACKGROUND THREAD — HARDWARE DATA ACQUISITION"]
        PIN["pin_to_cpu()\nsched_setaffinity"]
        PMU_OPEN["pmu_open() → perf_event_open()\n6 HW counters"]
        subgraph COUNTERS["CPU PMU Counters"]
            C0["Counter 0: CPU_CYCLES\n(critical, group leader)"]
            C1["Counter 1: INSTRUCTIONS\n(critical)"]
            C2["Counter 2: CACHE_MISSES\n(fallback → CACHE_REF → SW_CLOCK)"]
            C3["Counter 3: BRANCH_MISSES\n(optional)"]
            C4["Counter 4: BRANCH_INSTRUCTIONS\n(optional)"]
            C5["Counter 5: CACHE_REFERENCES\n(optional)"]
        end
        LOOP["Sampling Loop\nwhile (eng→running)"]
        SLEEP["nanosleep(1000µs)"]
        READ["pmu_read(&cur)\nread_scaled(fd)\nval × enabled/running"]
        DELTA["Delta Computation\ncur − prev for all 6 counters"]
        DERIVED["Derived Metrics\ncache_miss_rate = misses / instructions\nbranch_miss_rate = br_miss / br_inst\nipc = instructions / cycles"]
        SAMPLE["telemetry_sample_t\ntimestamp_ns + 6 raw + 3 derived"]
        PUSH["ringbuffer_push()\natomic, lock-free"]

        PIN --> PMU_OPEN --> COUNTERS --> LOOP
        LOOP --> SLEEP --> READ --> DELTA --> DERIVED --> SAMPLE --> PUSH
        PUSH --> LOOP
    end

    PUSH --> RINGBUF["Lock-Free SPSC Ring Buffer\n8192 slots, atomic head/tail\ncache-line padded"]
    RINGBUF --> POP["ringbuffer_pop()\n(main thread)"]
```

```mermaid
flowchart TB
    POP["ringbuffer_pop()"] --> PHASE_CHECK{Phase?}

    PHASE_CHECK -->|Learning| LEARN_LOOP

    subgraph LEARNING["PHASE 1: LEARNING (60s default)"]
        LEARN_LOOP["Learning Loop\nwhile elapsed < learning_duration"]
        LEARN_ACC["anomaly_learn()\nsum_cmr += cmr, sum_cmr² += cmr²\nsum_bmr += bmr, sum_bmr² += bmr²\nsum_ipc += ipc, sum_ipc² += ipc²\nn++"]
        LEARN_LOOP --> LEARN_ACC
        LEARN_ACC -->|"after 60s"| BASELINE
        BASELINE["anomaly_finalize_baseline()\nmean = Σx/n\nvar = E[x²]−(E[x])²\nstd = √var"]
        BASELINE --> PROFILE["baseline_profile_t\nmean_cmr, std_cmr\nmean_bmr, std_bmr\nmean_ipc, std_ipc\nready = true"]
    end

    PROFILE --> DROP["drop_privileges()\nsetuid/setgid → SUDO_UID"]
    DROP --> DETECT_LOOP

    PHASE_CHECK -->|Detection| DETECT_LOOP

    subgraph DETECTION["PHASE 2: DETECTION (continuous)"]
        DETECT_LOOP["Detection Loop\nwhile (!g_shutdown)"]
        DETECT_LOOP --> ZSCORE

        subgraph ZSCORE_BOX["Z-Score Computation"]
            ZSCORE["z = (value − mean) / std\nreturns 0 if std < 1e-12"]
            Z_CMR["z_cache_miss = z(cmr, mean, std)"]
            Z_BMR["z_branch_miss = z(bmr, mean, std)"]
            Z_IPC["z_ipc = z(ipc, mean, std)"]
            ZSCORE --> Z_CMR & Z_BMR & Z_IPC
        end

        Z_CMR & Z_BMR & Z_IPC --> THRESHOLD

        subgraph THRESHOLD_BOX["Threshold + Pattern Detection"]
            THRESHOLD["z_cmr > +3.5 → CACHE_MISS_SPIKE\nz_bmr > +3.5 → BRANCH_MISS_SPIKE\nz_ipc < −3.5 → IPC_COLLAPSE"]
            BURST["consecutive_anomalies ≥ 10\n→ BURST_PATTERN"]
            OSCIL["direction_changes ≥ cap/2\n→ OSCILLATION"]
            THRESHOLD --> BURST --> OSCIL
        end

        OSCIL --> COMPOSITE["Composite Score\nmax_z = max(|z_cmr|, |z_bmr|, |z_ipc|)\nscore = 1 − 1/(1 + max_z/3.5)\nrange [0.0 , 1.0]"]
    end
```

```mermaid
flowchart TB
    COMPOSITE["composite_score + anomaly_flags"] --> ALERT_CHECK{anomaly_flags ≠ 0?}
    ALERT_CHECK -->|No| NEXT["next sample"]
    ALERT_CHECK -->|Yes| ALERT_LEVEL

    subgraph ALERT_DECISION["ALERT LEVEL"]
        ALERT_LEVEL{"score > 0.8\nOR BURST?"}
        ALERT_LEVEL -->|Yes| CRIT["ALERT_CRITICAL"]
        ALERT_LEVEL -->|No| WARN_CHECK{"score > 0.5?"}
        WARN_CHECK -->|Yes| WARN["ALERT_WARNING"]
        WARN_CHECK -->|No| INFO["ALERT_INFO"]
    end

    CRIT & WARN & INFO --> CORR

    subgraph CORRELATION["CORRELATION ENGINE"]
        CORR["correlation_update()\npid, tid, score, timestamp"]
        RISK["process_risk_t\nEMA: α·score + (1−α)·prev  (α=0.3)\nsuspicious_samples++\n/proc/pid/comm"]
        DECAY["Periodic Decay (every 1s)\nscore *= 0.95\nif < 0.001 → 0.0\nif age > 30s → deactivate"]
        TOP["correlation_top_risk()\nhighest-scoring process"]
        CORR --> RISK --> DECAY
        CORR --> TOP
    end

    TOP --> OUTPUT

    subgraph OUTPUT_LAYER["OUTPUT"]
        OUTPUT["logger_alert()\nJSON, cooldown = 5s"]
        STDOUT["stdout\n(always on)"]
        LOGFILE["log file\n(-o flag)"]
        SYSLOG["syslog\n(-s flag)"]
        OUTPUT --> STDOUT & LOGFILE & SYSLOG
    end

    subgraph JSON_FORMAT["JSON Alert Format"]
        JSON["{
  level: CRITICAL,
  timestamp: 1708700000000000000,
  pid: 1234,
  comm: suspicious_proc,
  anomaly_score: 0.87,
  reason: cache_miss_spike burst_pattern
}"]
    end

    OUTPUT --> JSON_FORMAT
```

```mermaid
flowchart TB
    subgraph ML_HYBRID["ML HYBRID ARCHITECTURE — IPC DATA FLOW"]

        subgraph C_SIDE["C Process (cpu-guardian)"]
            C_MAIN["Main Loop"]
            C_DETECT["anomaly_detect()\nC fallback (z-score)"]
            IPC_SEND["ipc_socket_send()\n68 bytes per datagram"]
            C_MAIN --> C_DETECT
            C_MAIN --> IPC_SEND
        end

        IPC_SEND -->|"Unix Domain Socket\nSOCK_DGRAM, non-blocking\n/tmp/cpu-guardian.sock"| SOCK

        subgraph PY_SIDE["Python Process (guardian_ml.py)"]
            SOCK["Socket Receive\nstruct.unpack()"]
            FEAT["Feature Engineering (14 features)\nRaw: cmr, bmr, ipc (3)\nRolling Mean: window=32 (3)\nRolling Std: window=32 (3)\nDelta: rate of change (3)\nCross: cmr×ipc, bmr×ipc (2)"]
            SOCK --> FEAT

            FEAT --> ML_PHASE{Phase?}

            ML_PHASE -->|Learning| ACCUM["Accumulate 5000 samples"]
            ACCUM --> TRAIN["Train Models\nStandardScaler.fit()\nIsolationForest (n=200)\nOneClassSVM (nu=0.01)\nDiversity check"]

            ML_PHASE -->|Detection| SCALE["StandardScaler.transform()"]
            SCALE --> IF_MODEL["Isolation Forest\npredict() + score()"]
            SCALE --> SVM_MODEL["One-Class SVM\npredict() + score()"]

            IF_MODEL & SVM_MODEL --> ENSEMBLE{"Ensemble Decision"}
            ENSEMBLE -->|"Both = anomaly"| ML_CRIT["CRITICAL"]
            ENSEMBLE -->|"One = anomaly"| ML_WARN["WARNING"]
            ENSEMBLE -->|"Both = normal"| ML_NORM["NORMAL"]

            ML_NORM --> RETRAIN_BUF["Add to retrain buffer\n(normal samples only)"]
            RETRAIN_BUF -->|"every 5 min"| TRAIN

            ML_CRIT & ML_WARN --> ML_ALERT["JSON alert output\nif_score, svm_score\nmodel_agreement"]
        end
    end
```

```mermaid
flowchart TB
    subgraph SHUTDOWN["SHUTDOWN (SIGINT / SIGTERM)"]
        SIG["signal_handler()\ng_shutdown = 1"]
        SIG --> TEL_STOP["telemetry_stop()\nrunning=false\npthread_join\npmu_disable, pmu_close"]
        SIG --> ANOM_DEST["anomaly_destroy()\nfree(recent_cmr)"]
        SIG --> RB_DEST["ringbuffer_destroy()\nfree(buffer)"]
        SIG --> IPC_CLOSE["ipc_socket_close()"]
        TEL_STOP & ANOM_DEST & RB_DEST & IPC_CLOSE --> LOG_DEST["logger_destroy()\nfclose(file), closelog()"]
        LOG_DEST --> EXIT["Print summary\nTotal samples: N\nAnomalies: M\nEXIT_SUCCESS"]
    end

    subgraph DETECT_TABLE["Detection Capabilities"]
        direction LR
        subgraph C_DETECT_T["C-side (z-score fallback)"]
            D1["CACHE_MISS_SPIKE → Prime+Probe, Flush+Reload"]
            D2["BRANCH_MISS_SPIKE → Spectre branch abuse"]
            D3["IPC_COLLAPSE → Microarch contention"]
            D4["BURST_PATTERN → Active probing (10+ consecutive)"]
            D5["OSCILLATION → Cache thrashing / jitter"]
        end
        subgraph ML_DETECT_T["Python ML (ensemble primary)"]
            M1["Isolation Forest (n=200) → multi-modal, fast"]
            M2["One-Class SVM (nu=0.01) → tight boundary"]
            M3["Both agree → CRITICAL (5-10x FP reduction)"]
            M4["One flags → WARNING (early warning)"]
            M5["Retrain every 5min → adaptive, anti-poison"]
        end
    end

    subgraph MODULE_MAP["Module Dependency"]
        direction TB
        MAIN["main.c"] --> CONFIG_M["config.c/h"]
        MAIN --> PMU_M["pmu.c/h"]
        MAIN --> TEL_M["telemetry.c/h"]
        MAIN --> RB_M["ringbuffer.c/h"]
        MAIN --> ANOM_M["anomaly.c/h"]
        MAIN --> CORR_M["correlation.c/h"]
        MAIN --> LOG_M["logger.c/h"]
        MAIN --> IPC_M["ipc_socket.c/h"]
        PMU_M --> TEL_H["telemetry.h\n(telemetry_sample_t)"]
        TEL_M --> TEL_H
        ANOM_M --> TEL_H
        IPC_M --> TEL_H
        IPC_M -->|"Unix Socket"| ML_PY["guardian_ml.py\nnumpy + scikit-learn"]
    end
```

## Modules

### 1. PMU Interface Layer (`pmu.c/h`)
Wraps the Linux `perf_event_open` syscall. Monitors six hardware performance counters:
- **Cache references** and **cache misses** — detect cache-based attacks
- **Branch instructions** and **branch misses** — detect branch predictor abuse
- **Instructions retired** and **CPU cycles** — detect IPC anomalies

Supports per-core and per-process modes with automatic multiplexing scale factor correction.

### 2. Telemetry Engine (`telemetry.c/h`)
A dedicated sampling thread pinned to a CPU core via `sched_setaffinity`. Reads PMU counters at configurable intervals using `CLOCK_MONOTONIC_RAW` and computes delta-based derived metrics:
- `cache_miss_rate = cache_misses / instructions`
- `branch_miss_rate = branch_misses / branch_instructions`
- `ipc = instructions / cycles`

### 3. Lock-Free Ring Buffer (`ringbuffer.c/h`)
Single-producer / single-consumer ring buffer using C11 `<stdatomic.h>`:
- Power-of-2 capacity with bitmask indexing
- Cache-line padded head/tail to prevent false sharing
- Proper acquire/release memory ordering
- Zero-copy in-place writes

### 4. Statistical Anomaly Engine (`anomaly.c/h`)
The core detection logic operates in two phases:

**Learning Phase** (configurable, default 60s):
- Collects baseline statistics using Welford-style online mean/variance

**Detection Phase** (continuous):
- **Z-score analysis**: Flags samples where `|z| > threshold` for cache miss rate, branch miss rate, or IPC
- **Burst detection**: Tracks consecutive anomalous samples; fires `BURST_PATTERN` after N sustained anomalies
- **Oscillation detection**: Identifies high-frequency alternating patterns in the sliding window
- **Composite risk score**: Sigmoid-mapped maximum z-score, normalized to [0, 1]

### 5. Process Correlation Layer (`correlation.c/h`)
Maps detected anomalies to processes:
- Reads `/proc/[pid]/comm` for process identification
- Maintains per-PID risk scores with exponential moving average
- Applies time-based decay to prevent stale entries from persisting
- Tracks suspicious sample counts per process

### 6. Alert & Logging Engine (`logger.c/h`)
Outputs structured JSON alerts:
```json
{
  "level": "CRITICAL",
  "timestamp": 1234567890,
  "pid": 1234,
  "comm": "suspicious_proc",
  "anomaly_score": 0.87,
  "reason": "cache_miss_spike burst_pattern"
}
```
Supports stdout, file, and syslog backends with configurable cooldown to prevent alert storms.

### 7. Config System (`config.c/h`)
Parses key=value config files and CLI arguments:
```
sampling_interval_us=1000
learning_duration_sec=60
z_threshold=3.5
burst_window=10
```

---

## Detection Logic

### What CPU Guardian detects:

| Pattern | Indicator | Attack Type |
|---------|-----------|-------------|
| Cache miss rate spike | Z-score > threshold | Prime+Probe, Flush+Reload |
| Branch miss rate spike | Z-score > threshold | Spectre-variant branch abuse |
| IPC collapse | Negative Z-score | Microarchitectural contention |
| Sustained burst | N consecutive anomalies | Active side-channel probing |
| Oscillation pattern | Rapid high/low alternation | Timed probing sequences |

### How it differs from traditional IDS:
1. **Hardware-level telemetry** — operates below the OS, using CPU performance counters that cannot be spoofed by userspace malware
2. **Behavioral, not signature-based** — detects statistical anomalies rather than known attack patterns
3. **Minimal overhead** — lock-free architecture, < 5% CPU impact
4. **Real-time** — microsecond-resolution sampling with nanosecond timestamps
5. **Research-oriented** — extensible baseline and detection algorithms

---

## Platform requirements

- **OS**: Linux (kernel 3.14+ with `perf_event_open`; tested on Ubuntu 22.04+)
- **Architecture**: x86_64 (PMU events used are standard Linux `PERF_TYPE_HARDWARE`; no CPU-model-specific events)
- **Privileges**: Root or `CAP_PERFMON` for PMU access; the process drops privileges after opening counters when run via `sudo`
- **VM**: Works on bare metal. Inside VMs, PMU support is often limited: the code uses only generic hardware events (cycles, instructions, cache_misses, branch_misses, etc.) and does **not** use `topdown-*`, `TOPDOWN.SLOTS`, or `cycles:u`-style events. If your VM returns ENOENT for `cpu=-1`, the code falls back to `cpu=0` automatically. For best results, run on real hardware or a VM with PMU passthrough.

---

## Build

Requires Linux x86_64 with kernel support for `perf_event_open`.

**Recommended compiler flags** (already used by the Makefile):  
`-std=c17 -Wall -Wextra -Wpedantic -O2 -D_GNU_SOURCE`

```bash
# Release build
make

# Debug build with AddressSanitizer + UBSan
make debug

# Build synthetic test workloads
make test

# Clean
make clean
```

## Usage

```bash
# System-wide monitoring (requires root or CAP_PERFMON)
sudo ./bin/cpu-guardian -v

# Monitor specific CPU core
sudo ./bin/cpu-guardian -C 0 -v

# Monitor specific process
sudo ./bin/cpu-guardian -p 1234 -v

# Use config file
sudo ./bin/cpu-guardian -c guardian.conf -v

# Custom parameters
sudo ./bin/cpu-guardian -i 500 -l 30 -z 3.0 -o /tmp/alerts.log -v
```

### Hybrid mode (C + ML)

Optional Python ML engine (Isolation Forest + One-Class SVM) receives samples over a Unix socket. If the ML process is not running, the C binary uses only its built-in z-score detection.

```bash
# Terminal 1: start ML engine first (binds socket)
cd ml/
pip install -r requirements.txt
python3 guardian_ml.py --verbose

# Terminal 2: start C collector (sends to socket; default path /tmp/cpu-guardian.sock)
sudo ./bin/cpu-guardian -c guardian.conf -v
```

Use `-S PATH` to set socket path, or `-M` to disable ML output (C-only detection). See [PIPELINE.txt](PIPELINE.txt) for the full IPC and ML flow.

### CLI Options
```
  -c FILE    Configuration file path
  -i USEC    Sampling interval (microseconds)
  -l SEC     Learning duration (seconds)
  -z THRESH  Z-score threshold
  -C CPU     Target CPU core (-1 = all)
  -p PID     Target PID (-1 = system-wide)
  -o FILE    Log output file
  -s         Enable syslog output
  -v         Verbose mode
  -T         PMU test mode: open counters, read once, print raw values, exit
  -S PATH    ML engine Unix socket path (default: /tmp/cpu-guardian.sock)
  -M         Disable ML output (C-only detection)
  -h         Show help
```

### Runtime compatibility (perf events)

CPU Guardian uses only these standard Linux PMU events (no topdown, no `:u` modifiers):

- `PERF_COUNT_HW_CPU_CYCLES`
- `PERF_COUNT_HW_INSTRUCTIONS`
- `PERF_COUNT_HW_CACHE_MISSES` (fallback: CACHE_REFERENCES, then SW CPU_CLOCK)
- `PERF_COUNT_HW_BRANCH_MISSES`
- `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`
- `PERF_COUNT_HW_CACHE_REFERENCES` (optional)

To see what your kernel supports: `perf list hardware` and `perf list software`. If cycles and instructions are available, the detector can run; other events degrade gracefully (unopened counters read as 0).

## Testing

Run the synthetic workload generator alongside cpu-guardian:

```bash
# Terminal 1: Start the detector
sudo ./bin/cpu-guardian -v -l 10

# Terminal 2: Run normal baseline (mode 1)
./bin/test_synthetic 1 30

# Terminal 2: Run cache stress attack (mode 2)
./bin/test_synthetic 2 30

# Terminal 2: Run branch misprediction attack (mode 3)
./bin/test_synthetic 3 30

# Terminal 2: Run mixed attack pattern (mode 4)
./bin/test_synthetic 4 30
```

### Test Modes:
| Mode | Description | Expected Detection |
|------|-------------|-------------------|
| 1 | Sequential access, predictable branches | No anomalies (baseline) |
| 2 | Random 64MB access (cache thrashing) | `cache_miss_spike`, `burst_pattern` |
| 3 | Unpredictable branch patterns | `branch_miss_spike` |
| 4 | Alternating cache + branch bursts | Multiple flags, `oscillation` |

---

## Performance

- **Target overhead**: < 5% CPU
- **Architecture**: Lock-free SPSC ring buffer, dedicated sampling thread
- **Memory**: Fixed allocation at startup, no runtime heap allocations in hot path
- **Scalability**: One telemetry thread per monitored core

## Security Considerations

- Requires `root` or `CAP_PERFMON` capability for PMU access
- Drops privileges after PMU initialization when run via `sudo`
- All buffer sizes are bounded; no unbounded allocations
- Built with `-Wall -Wextra -Wpedantic`; debug mode includes AddressSanitizer

## Future Extensions

- eBPF integration for kernel-level event correlation
- Hypervisor-level monitoring (KVM/Xen)
- Online clustering for unsupervised anomaly grouping
- Risk heatmap visualization
- Web dashboard with real-time charts
- Adaptive sampling interval based on system load
- Multi-core coordinated detection

---

## Research Background

CPU side-channel attacks exploit shared microarchitectural resources (caches, branch predictors, TLBs) to leak information across security boundaries. Notable attacks include:

- **Spectre** (CVE-2017-5753, CVE-2017-5715) — branch prediction abuse
- **Meltdown** (CVE-2017-5754) — out-of-order execution
- **Prime+Probe** — cache set contention timing
- **Flush+Reload** — shared cache line monitoring

CPU Guardian provides a runtime behavioral detection layer that complements hardware/firmware mitigations by monitoring the statistical footprint these attacks leave in PMU counter data.

## License

Research / Educational use.

---

## Repository layout

```
cpu-guardian/
├── PIPELINE.txt      # Full system pipeline diagram (config → detection → ML)
├── README.md
├── Makefile
├── guardian.conf     # Default config (key=value)
├── LICENSE
├── .gitignore
├── src/              # C source
│   ├── main.c
│   ├── config.c, config.h
│   ├── pmu.c, pmu.h
│   ├── telemetry.c, telemetry.h
│   ├── ringbuffer.c, ringbuffer.h
│   ├── anomaly.c, anomaly.h
│   ├── correlation.c, correlation.h
│   ├── logger.c, logger.h
│   └── ipc_socket.c, ipc_socket.h
├── ml/               # Optional ML detection engine
│   ├── guardian_ml.py
│   └── requirements.txt
├── tests/
│   └── test_synthetic.c
├── bin/               # Created by make (cpu-guardian, test_synthetic)
└── obj/               # Created by make (.o files)
```

For a detailed visual pipeline (data flow, formulas, wire format), see **[PIPELINE.txt](PIPELINE.txt)**.
