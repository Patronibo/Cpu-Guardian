/*This ring buffer implementation is a carefully designed, lock-free, single-producer/single-
consumer queue tailored for high-frequency telemetry transport inside CPU Guardian. It prioritizes 
predictable performance, minimal synchronization overhead, and cache-friendly behavior—exactly what 
you want in a low-latency monitoring pipeline.
The next_power_of_two helper is a classic bit-manipulation routine that rounds a given capacity 
up to the nearest power of two. This design choice is intentional and performance-driven: by ensuring 
the capacity is a power of two, index wrapping can be implemented using a bitmask (& (capacity - 1)) 
instead of a modulo operation. Bitmasking is significantly faster and branch-free, which matters in 
tight producer/consumer loops.
ringbuffer_init normalizes the requested capacity, allocates a zero-initialized buffer with calloc, 
and initializes the atomic head and tail indices using relaxed memory ordering. The use of atomics 
instead of mutexes indicates this structure is meant for concurrent contexts without locking. Since 
it does not use compare-and-swap or complex contention logic, the design strongly implies a single 
producer and single consumer model, which keeps synchronization simple and efficient.
The ringbuffer_push function represents the producer side. It loads head with relaxed ordering and 
tail with acquire semantics to ensure visibility of consumer updates. The next index is calculated 
with (head + 1) & (capacity - 1), and if advancing would collide with tail, the buffer is considered 
full. Data is written directly into the buffer slot before publishing the new head using a release 
store. This release operation guarantees that the sample write becomes visible to the consumer before 
the head index update is observed.
Conversely, ringbuffer_pop handles the consumer side. It reads tail relaxed and head with acquire ordering 
to ensure it sees the latest produced elements. If tail == head, the buffer is empty. Otherwise, it copies 
out the sample and advances tail using a release store, ensuring correct ordering for the producer’s 
perspective.
ringbuffer_count computes the number of elements using masked subtraction, which works because capacity 
is a power of two and indices wrap naturally. ringbuffer_empty simply checks if the count is zero.
Overall, this implementation is efficient, memory-order aware, and free of unnecessary locking. It 
reflects a solid understanding of atomic semantics and real-time system constraints, making it well-
suited for streaming telemetry between performance monitoring and anomaly detection components 
without introducing scheduling bottlenecks.
*/

#include "ringbuffer.h"

#include <stdlib.h>
#include <string.h>

static size_t next_power_of_two(size_t v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

int ringbuffer_init(ringbuffer_t *rb, size_t capacity)
{
    if (!rb || capacity == 0) return -1;

    capacity = next_power_of_two(capacity);

    rb->buffer = calloc(capacity, sizeof(telemetry_sample_t));
    if (!rb->buffer) return -1;

    rb->capacity = capacity;
    atomic_store_explicit(&rb->head, 0, memory_order_relaxed);
    atomic_store_explicit(&rb->tail, 0, memory_order_relaxed);

    return 0;
}

void ringbuffer_destroy(ringbuffer_t *rb)
{
    if (!rb) return;
    free(rb->buffer);
    rb->buffer   = NULL;
    rb->capacity = 0;
}

bool ringbuffer_push(ringbuffer_t *rb, const telemetry_sample_t *sample)
{
    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_acquire);

    size_t next = (head + 1) & (rb->capacity - 1);
    if (next == tail) return false;   /* full */

    rb->buffer[head] = *sample;

    atomic_store_explicit(&rb->head, next, memory_order_release);
    return true;
}

bool ringbuffer_pop(ringbuffer_t *rb, telemetry_sample_t *out)
{
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
    size_t head = atomic_load_explicit(&rb->head, memory_order_acquire);

    if (tail == head) return false;   /* empty */

    *out = rb->buffer[tail];

    size_t next = (tail + 1) & (rb->capacity - 1);
    atomic_store_explicit(&rb->tail, next, memory_order_release);
    return true;
}

size_t ringbuffer_count(const ringbuffer_t *rb)
{
    size_t head = atomic_load_explicit(&((ringbuffer_t *)rb)->head,
                                       memory_order_acquire);
    size_t tail = atomic_load_explicit(&((ringbuffer_t *)rb)->tail,
                                       memory_order_acquire);
    return (head - tail) & (rb->capacity - 1);
}

bool ringbuffer_empty(const ringbuffer_t *rb)
{
    return ringbuffer_count(rb) == 0;
}
