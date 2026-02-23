/*This module implements a lightweight, non-blocking inter-process communication (IPC)
layer built specifically for Linux systems, and it is clearly designed to stream telemetry data
from the CPU monitoring component to an external machine learning (ML) engine in a
robust and low-latency manner. The #ifndef __linux__ guard at the top immediately
enforces a strict platform requirement, making it explicit that the implementation depends
on Linux-specific primitives such as Unix domain sockets and the /proc ecosystem. This
design decision signals that portability is intentionally sacrificed in favor of tight
integration with Linux kernel facilities, which is typical for high-performance observability
agents.
The ipc_socket_init function establishes a Unix domain datagram socket (AF_UNIX,
SOCK_DGRAM), which is a deliberate architectural choice. By using datagram semantics
instead of stream sockets, the code ensures that each telemetry sample is transmitted as
an atomic message, eliminating the need for framing logic on the receiving side. This
simplifies the protocol and reduces overhead. The socket is immediately configured to
operate in non-blocking mode using fcntl, which is critical in a monitoring context: the
telemetry pipeline must never stall the main sampling loop if the ML engine is slow or
temporarily unavailable. The function constructs a sockaddr_un structure, copies the
provided socket path safely using strncpy, and attempts to connect to the ML engine
endpoint. Notably, even though Unix datagram sockets do not require a persistent
connection in the TCP sense, calling connect allows subsequent send calls to omit
explicit destination addressing, improving efficiency and code clarity. Error handling is
explicit and verbose, printing diagnostic messages that hint at operational scenarios such
as the ML engine not yet running. This improves debuggability in distributed deployments.
The ipc_socket_send function serializes a telemetry_sample_t structure into a wire-
friendly representation (ipc_sample_wire_t) before transmission. This explicit field-by-
field copy is a subtle but important design choice: it decouples the internal telemetry
structure from the wire format, allowing the internal representation to evolve without
necessarily breaking the IPC protocol. The transmitted fields include low-level hardware
performance counters (cache references, cache misses, branch instructions, branch misses,
cycles, instructions) as well as derived metrics (cache miss rate, branch miss rate, IPC),
indicating that the ML engine receives both raw signals and precomputed ratios. This
hybrid strategy can reduce feature-engineering overhead on the ML side while preserving
flexibility.
Transmission is performed using send with both MSG_DONTWAIT and MSG_NOSIGNAL.
MSG_DONTWAIT reinforces the non-blocking design, ensuring the sender never blocks under
backpressure, while MSG_NOSIGNAL prevents SIGPIPE from being raised if the receiving
end disappears—an important robustness measure in long-running daemons. The error
handling logic explicitly tolerates transient conditions such as EAGAIN, EWOULDBLOCK, and
ECONNREFUSED, returning a failure code silently so the caller can decide whether to retry or
ignore the dropped sample. This suggests that telemetry loss is considered acceptable
under overload conditions, prioritizing system stability over guaranteed delivery. Only
unexpected errors are logged, which prevents log flooding in high-frequency sampling
scenarios.
Finally, ipc_socket_close cleanly releases the file descriptor if valid, adhering to
straightforward resource management principles. Overall, this module reflects a
performance-conscious, failure-tolerant IPC design optimized for high-frequency
telemetry streaming to an external analytics or ML component. It embraces non-blocking
semantics, atomic datagram messaging, explicit error handling, and Linux-native
communication primitives to ensure that the monitoring pipeline remains lightweight,
resilient, and minimally intrusive to the observed system.
*/

#ifndef __linux__
#error "cpu-guardian requires Linux"
#endif

#include "ipc_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

int ipc_socket_init(const char *socket_path)
{
    if (!socket_path || socket_path[0] == '\0') return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ipc] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ipc] connect(%s) failed: %s (ML engine not running yet?)\n",
                socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(stderr, "[ipc] connected to ML engine at %s\n", socket_path);
    return fd;
}

int ipc_socket_send(int fd, const telemetry_sample_t *sample)
{
    if (fd < 0 || !sample) return -1;

    ipc_sample_wire_t wire;
    wire.timestamp_ns        = sample->timestamp_ns;
    wire.cache_references    = sample->cache_references;
    wire.cache_misses        = sample->cache_misses;
    wire.branch_instructions = sample->branch_instructions;
    wire.branch_misses       = sample->branch_misses;
    wire.cycles              = sample->cycles;
    wire.instructions        = sample->instructions;
    wire.cache_miss_rate     = sample->cache_miss_rate;
    wire.branch_miss_rate    = sample->branch_miss_rate;
    wire.ipc                 = sample->ipc;

    ssize_t n = send(fd, &wire, sizeof(wire), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED)
            return -1;
        fprintf(stderr, "[ipc] send failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

void ipc_socket_close(int fd)
{
    if (fd >= 0)
        close(fd);
}
