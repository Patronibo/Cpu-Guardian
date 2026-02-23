/*This header file defines the public interface and wire-level contract for the IPC layer that
bridges the low-level C telemetry collector with the higher-level Python-based machine
learning engine, and its structure reveals a careful focus on binary compatibility,
performance, and predictable behavior across language boundaries. At its core is the
ipc_sample_wire_t structure, which represents the exact byte-level format transmitted
over the Unix domain socket. The use of __attribute__((packed)) is a critical design
decision: it forces the compiler to eliminate any padding that might otherwise be inserted
for alignment purposes, guaranteeing that the memory layout is deterministic and
identical to what a Python receiver expects when using struct.unpack. This makes the
struct not merely a data container, but effectively a protocol specification. In cross-
language IPC systems, implicit padding differences can silently corrupt data interpretation,
so explicitly packing the structure demonstrates awareness of ABI-level pitfalls and a
commitment to stable interoperability.
The structure itself contains both raw hardware performance counter values—such as
cache_references, cache_misses, branch_instructions, branch_misses, cycles, and
instructions—and derived metrics like cache_miss_rate, branch_miss_rate, and ipc
(instructions per cycle). Including both absolute counters and normalized ratios indicates
that the system is designed to offload some feature engineering to the C layer, likely to
reduce computational overhead in Python or to ensure consistent metric definitions across
components. The presence of a nanosecond-resolution timestamp_ns field suggests that
temporal ordering and high-resolution time correlation are important for downstream ML
analysis, potentially for sequence modeling or anomaly detection over sliding windows.
The function prototypes formalize a minimal yet robust lifecycle for this IPC mechanism.
ipc_socket_init establishes a non-blocking Unix domain datagram socket, reinforcing a
design principle where the telemetry producer must never stall due to backpressure from
the ML consumer. This is explicitly documented in the comment, which clarifies that the C
side should continue operating even if Python is not listening. The return convention—file
descriptor on success, -1 on failure—follows standard Unix idioms and integrates
naturally into event-driven or polling-based architectures. Similarly, ipc_socket_send
transmits a single telemetry sample and uses a simple success/failure contract, where -1
may indicate transient conditions such as the ML engine not yet being ready. This implies
that telemetry delivery is best-effort rather than guaranteed, prioritizing system stability
and low latency over strict reliability. Finally, ipc_socket_close encapsulates resource
cleanup, maintaining a clean abstraction boundary and preventing file descriptor leaks.
Overall, this header defines more than just function signatures; it codifies a compact,
binary-stable, cross-language telemetry protocol optimized for high-frequency data
streaming in a Linux environment. Its emphasis on packed structures, non-blocking
semantics, and minimal overhead aligns with the needs of real-time monitoring systems
where performance isolation, deterministic behavior, and interoperability between C and
Python components are essential.
*/

#ifndef CPUGUARD_IPC_SOCKET_H
#define CPUGUARD_IPC_SOCKET_H

#include "telemetry.h"


typedef struct __attribute__((packed)) {
    uint64_t timestamp_ns;
    uint64_t cache_references;
    uint64_t cache_misses;
    uint64_t branch_instructions;
    uint64_t branch_misses;
    uint64_t cycles;
    uint64_t instructions;
    float    cache_miss_rate;
    float    branch_miss_rate;
    float    ipc;
} ipc_sample_wire_t;


int  ipc_socket_init(const char *socket_path);


int  ipc_socket_send(int fd, const telemetry_sample_t *sample);


void ipc_socket_close(int fd);

#endif 
