Working solution for HW1 for jmt2235.
Environment used: Debian 12 vm

Initial flow involved attempting to get something like SEC("tracepoint/block/...") working but I quickly realized that was not correct as the IO Request Latency Histogram should be derived directly from the structure and requirements of monitoring block I/O request latencies. I tried for around 4-5 days to get SEC("tracepoint/block/...") to work, so that was the largest hurdle. I moved onto having a BPF_printk every I/O request and then moved onto actually implementing the histogram. it uses 2 ds's as explained in the code.

To run the code:
./histogram <number greater than 0 and less than 60>. 
There are a plethora of settings you can tweak in the code

(OPTIONAL)
there's also a shell script that runs fio in the background, you'd need to open another terminal and just run ./run.sh and it should automatically open and begin background work!

There is a sample run of running the ./histogram 5 and ./run.sh concurrrently showing the increase in counts as background work begins
