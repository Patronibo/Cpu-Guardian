/*This header defines a carefully engineered lock-free ring buffer interface designed 
specifically for high-throughput, low-latency telemetry exchange inside CPU Guardian. 
It formalizes a single-producer / single-consumer (SPSC) concurrency model, which allows 
the implementation to avoid heavy synchronization primitives while still remaining 
thread-safe.
One of the most important design decisions is explicitly documented: the buffer capacity 
must be a power of two. This constraint enables index wrapping through bitmasking instead 
of modulo division, significantly improving performance in tight loops. The implementation 
guarantees this invariant during initialization by rounding up to the next power of two, 
ensuring both correctness and efficiency.
The ringbuffer_t structure is optimized with hardware-level considerations in mind. The 
head and tail indices are declared as atomic_size_t, making them safe for concurrent 
access between producer and consumer threads. More importantly, each is explicitly aligned 
to CACHE_LINE_SIZE (64 bytes) using _Alignas. This padding prevents false sharing—an issue 
where two frequently modified variables reside on the same cache line and cause unnecessary 
cache coherency traffic between CPU cores. By isolating head and tail onto separate cache 
lines, the design minimizes cross-core contention and preserves predictable performance 
under load.
The API exposes a minimal and clear lifecycle: ringbuffer_init allocates and prepares the 
buffer, ringbuffer_destroy frees its memory, ringbuffer_push and ringbuffer_pop implement 
non-blocking producer and consumer operations, and helper functions like ringbuffer_count 
and ringbuffer_empty provide safe introspection. Importantly, both push and pop operations 
are non-blocking and return boolean success indicators, meaning the caller must handle full 
or empty conditions explicitly—this avoids hidden stalls and keeps timing behavior 
deterministic.
Overall, this header demonstrates a strong awareness of modern CPU memory hierarchies, atomic 
memory ordering, and real-time system constraints. It establishes a clean, performance-oriented 
concurrency primitive that fits naturally into a streaming telemetry architecture without introducing 
locks, dynamic resizing, or unpredictable scheduling delays.
*/

#ifndef CPUGUARD_RINGBUFFER_H
#define CPUGUARD_RINGBUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "telemetry.h"


#define CACHE_LINE_SIZE 64


typedef struct {
    telemetry_sample_t *buffer;
    size_t              capacity;     

    
    _Alignas(CACHE_LINE_SIZE) atomic_size_t head;
    _Alignas(CACHE_LINE_SIZE) atomic_size_t tail;
} ringbuffer_t;


int ringbuffer_init(ringbuffer_t *rb, size_t capacity);


void ringbuffer_destroy(ringbuffer_t *rb);


bool ringbuffer_push(ringbuffer_t *rb, const telemetry_sample_t *sample);


bool ringbuffer_pop(ringbuffer_t *rb, telemetry_sample_t *out);

size_t ringbuffer_count(const ringbuffer_t *rb);


bool ringbuffer_empty(const ringbuffer_t *rb);

#endif 
