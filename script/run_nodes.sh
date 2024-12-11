#!/bin/bash

cd /root/code_dev/tee-dao
mkdir -p ./log

# Run 3 nodes with IDs 1, 2, and 3
go build -o participant_node main.go

# Run coordinator
go run coordinator/cmd/main.go > ./log/coordinator_log 2>&1 &

sleep 3

# Start node 0
./participant_node -n=node0 > ./log/node0_log 2>&1 &
pid0=$!

# Start node 1
./participant_node -n=node1 > ./log/node1_log 2>&1 &
pid1=$!

# Start node 2
./participant_node -n=node2 > ./log/node2_log 2>&1 & 
pid2=$!