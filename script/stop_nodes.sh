#!/bin/bash

# Get the PIDs of all processes with the name 'participant_nod'
pids=$(ps -ef | grep participant_nod | grep -v grep | awk '{print $2}')

# Check if there are any PIDs found
if [ -z "$pids" ]; then
  echo "No processes with the name 'participant_nod' found."
else
  # Kill each process by PID
  echo "Killing the following PIDs: $pids"
  for pid in $pids; do
    kill -9 $pid
    echo "Killed process with PID: $pid"
  done
fi
