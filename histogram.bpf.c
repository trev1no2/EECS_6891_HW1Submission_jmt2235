#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 
 * Map to store the start time of each request. The key is the request address,
 * and the value is the start time in nanoseconds.
 * essentially a hashmap to store the start times of individual I/O requests
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // Using the request address as the key
    __type(value, u64); // Start time in nanoseconds
    __uint(max_entries, 4096); // arbitrarily chosen, but max # of processes per bucket
} start_times SEC(".maps");

/* 
 * Array map to store the count of requests falling into each latency bucket.
 * The key is the index of the latency bucket, and the value is the count of
 * requests. The size and range of latency buckets could  be adjusted as needed.
 * essentially an array to store the histogram of I/O latencies (bucketed by latency ranges)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32); // Latency bucket index
    __type(value, u64); // Count of requests in this latency bucket
    __uint(max_entries, 64); // arbitrarily chosen
} latencies SEC(".maps");

void record_start_time(u64 req_address) {
    u64 time = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &req_address, &time, BPF_ANY);
}

int compute_bucket(u64 latency_us) {
    for (u32 i = 0; i < 64; i++) {
        if (latency_us < (1ULL << (i + 1)))
            return i;
    }
    return 63; // Last bucket for any latency above max range
}

void update_latency_histogram(u64 req_address) {
    u64* start_time = bpf_map_lookup_elem(&start_times, &req_address);
    if (start_time) {
        u64 end_time = bpf_ktime_get_ns();
        u64 diff = end_time - *start_time;
        u32 bucket = compute_bucket(diff / 1000); // Convert nanoseconds to microseconds and compute bucket

        // Look up the current count for this latency bucket
        u64* existing_count = bpf_map_lookup_elem(&latencies, &bucket);
        u64 count = existing_count ? *existing_count + 1 : 1; // If exists, increment the count, otherwise start at 1

        // Update the latencies map with the new count
        bpf_map_update_elem(&latencies, &bucket, &count, BPF_ANY);

        // Remove the start time entry as it's no longer needed
        bpf_map_delete_elem(&start_times, &req_address);
    }
}


/* Tracepoint hook for block request insertions. Records start time. */
SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq) {
    u64 req_address = (u64)rq;
    record_start_time(req_address);
    return 0;
}

/* Tracepoint hook for block request completions. Updates latency histogram. */
SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq) {
    u64 req_address = (u64)rq;
    update_latency_histogram(req_address);
    return 0;
}
