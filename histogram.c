#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

static volatile bool exiting = false;
#define INT_MAX 60 // 1 min max waiting period

#define MAX_LATENCY_BUCKETS 18 // num rows, change for higher latencies

void sig_handler(int sig) {
    exiting = true;
}

// calculate the upper limit of each bucket
unsigned long long calculate_bucket_upper_limit(int index) {
    // Base case: the first bucket has an upper limit of 1
    if (index == 0) return 1;
    // For other indexes, calculate the upper limit as 2^index - 1 using bit shift
    return (1ULL << index) - 1;
}

// print the histogram neatly
int print_latency_histogram(int latency_map_fd) {
    printf("%-20s : %-16s | %s\n", "usecs range", "count", "distribution");

    // Loop through each bucket to calculate its range and print its distribution
    for (unsigned int key = 0; key < MAX_LATENCY_BUCKETS; key++) {
        // Calculate lower and upper limits of the current bucket
        unsigned long long lower_limit = key == 0 ? 0 : calculate_bucket_upper_limit(key) + 1;
        unsigned long long upper_limit = calculate_bucket_upper_limit(key + 1);

        unsigned long long value;
        // Attempt to retrieve the bucket's value from the latency map
        int res = bpf_map_lookup_elem(latency_map_fd, &key, &value);
        if (res == 0) {
            // Print the bucket's range and value
            printf("%-10llu -> %-10llu : %-16llu | ", lower_limit, upper_limit, value);
            // Print a capped number of stars to represent the bucket's value visually
            for (int i = 0, print_stars = value > 50 ? 50 : value; i < print_stars; i++) printf("*");
            printf("\n");
        } else {
            // Handle missing entries by printing a 0 count
            printf("%-10llu -> %-10llu : %-16s | \n", lower_limit, upper_limit, "0");
        }
    }
    return 0;
}
// ChatGPT provided to ensure we only get numbers
bool is_number(const char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') return false;
    }
    return true;
}

int main(int argc, char **argv) {

    // start of chatGPT provided code for numbers only (I included some other stuff it's not directly from gpt)
    if (argc < 2) {
        fprintf(stderr, "No time period supplied. Example usage: sudo ./histogram.out 5\n");
        return 1;
    }
    
    if (!is_number(argv[1])) {
        fprintf(stderr, "Supplied time period is not a valid number.\n");
        return 1;
    }
    
    char* endptr;
    long interval = strtol(argv[1], &endptr, 10);
    // Check for conversion errors (no digits found, or not the entire string was consumed)
    if (endptr == argv[1] || *endptr != '\0') {
        fprintf(stderr, "Invalid number: %s\n", argv[1]);
        return 1;
    }
    // Check for valid range of interval
    if (interval <= 0 || interval > INT_MAX) {
        fprintf(stderr, "Interval value out of valid range. (0 < time period < 1 min)\n");
        return 1;
    }
    // end of chatGPT provided code for numbers only

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[2];
    int prog_fd;

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("histogram.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Attach BPF program
    char *prog_names[] = {"block_rq_insert",
                          "block_rq_complete"};
    for (int i = 0; i < 2; i++) {
        printf("Attaching program %s\n", prog_names[i]);
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "ERROR: finding BPF program failed\n");
            return 1;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting BPF program FD failed\n");
            return 1;
        }
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: Attaching BPF program failed\n");
            return 1;
        }
    }

    // Find and get a reference to the latency histogram map
    struct bpf_map *latency_map = bpf_object__find_map_by_name(obj, "latencies");
    int latency_map_fd = bpf_map__fd(latency_map);
    if (latency_map_fd < 0) {
        fprintf(stderr, "ERROR: Failed to find latency histogram map\n");
        return 1;
    }

    // Setup signal handler for graceful termination
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("BPF program loaded and attached. Printing histogram every %ld seconds.\n", interval);
    while (!exiting) {
        print_latency_histogram(latency_map_fd); // Call with the file descriptor
        // Reset histogram counts in BPF program
        for (int i = 0; i < MAX_LATENCY_BUCKETS; i++) {
            __u64 zero = 0;
            bpf_map_update_elem(latency_map_fd, &i, &zero, BPF_ANY);
        }
        sleep(interval);
    }

    // Cleanup
    for (int i = 0; i < 2; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}