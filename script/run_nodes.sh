#!/bin/bash

# Run 3 nodes with IDs 1, 2, and 3
go build -o participant_node main.go

# Start node 0
./participant_node -n=node0 > log0 2>&1 &
pid0=$!

# Start node 1
./participant_node -n=node1 > log1 2>&1 &
pid1=$!

# Start node 2
./participant_node -n=node2 > log2 2>&1 & 
pid2=$!