#!/bin/bash

WORKDIR="/tmp/test_io_stuff"
FILE="$WORKDIR/mytestfile"
FILESIZE="50M"
DURATION="300" # just run it for 5 mins
IO_TYPE="libaio"
NO_CACHE=1

# make sure the directory is there
mkdir -p $WORKDIR

# starting fio
echo "Kicking off disk I/O, hang tight..."
fio --name=test_io --rw=randrw --bs=4k --size=$FILESIZE --numjobs=2 --time_based --runtime=${DURATION}s --ioengine=$IO_TYPE --direct=$NO_CACHE --filename=$FILE --group_reporting &

PID_OF_FIO=$!

echo "Some disk I/O is now running in the background, PID is: $PID_OF_FIO"
echo "It'll run for $DURATION seconds. If you wanna kill it, do 'kill $PID_OF_FIO'."

# Wait here until the fio job is done or gets killed
wait $PID_OF_FIO

# all done, clean up
rm -rf $WORKDIR
echo "All done with the I/O. Cleaned up the temp. GOodbye cruel world"
