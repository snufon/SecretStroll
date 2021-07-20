#!/bin/bash
set -o errexit
trap "kill 0" EXIT

grid_id=1

#while true; do
#tcp_dump -w captured;
for grid_id in {1..100}; do
    for i in {1..20}; do
        for n in {1..5};do 
            echo captured_${grid_id}_${i}
            (tcpdump -w captured_traffic_full/captured_${grid_id}_${i}) &
            pid1=$!
            echo $pid1
            sleep 1
            python3 client.py grid $grid_id --tor > /dev/null && echo $pid1 && kill -2 $pid1 && break
            echo $pid1
            kill -2 $pid1
        done
 
    done
done
