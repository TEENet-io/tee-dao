#!/bin/bash

mkdir -p ./log

# Build participant and coordinator
go build -o participant_node main.go
go build -o coordinator_node coordinator/cmd/main.go

# Run coordinator
./coordinator_node > ./log/coordinator_log 2>&1 &
coordinator_pid=$!
echo "Coordinator PID: $coordinator_pid"

sleep 3

# Run 3 nodes with IDs 1, 2, and 3
# Start node 0
./participant_node -n=node0 > ./log/node0_log 2>&1 &
pid0=$!
echo "Node 0 PID: $pid0"

# Start node 1
./participant_node -n=node1 > ./log/node1_log 2>&1 &
pid1=$!
echo "Node 1 PID: $pid1"

# Start node 2
./participant_node -n=node2 > ./log/node2_log 2>&1 & 
pid2=$!
echo "Node 2 PID: $pid2"