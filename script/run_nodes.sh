#!/bin/bash

# Set GODEBUG to disable CGO check for all Go processes in this script
export GODEBUG=cgocheck=0

# Run 3 nodes with IDs 1, 2, and 3
go build -o participant_node main.go

# Start node 0
./participant_node -id=0 > log0 2>&1 &
pid0=$!

# Start node 1
./participant_node -id=1 > log1 2>&1 &
pid1=$!

# Start node 2
./participant_node -id=2 > log2 2>&1 & 
pid2=$!