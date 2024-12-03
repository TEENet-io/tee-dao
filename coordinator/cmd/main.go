package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee-dao/coordinator"
	"tee-dao/utils"
)

func main() {
	// Step 1: Load Configurations
	coordinatorConfig, err := utils.LoadCoordinatorConfig("config/coordinator_config.json")
	if err != nil {
		log.Fatalf("Error loading coordinator config: %v", err)
	}
	// Step 2: Initialize coordinator and start
	coordinator, err := coordinator.NewCoordinator(coordinatorConfig)
	if err != nil {
		log.Fatalf("Error creating coordinator: %v", err)
	}

	// Start the participant
	if err := coordinator.Start(); err != nil {
		log.Fatalf("Failed to start coordinator: %v", err)
	}
	defer coordinator.Close()

	// Set up WaitGroup and signal handling to wait until we receive a termination signal
	var wg sync.WaitGroup
	wg.Add(1)

	// Listen for OS interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		coordinator.Close()
		wg.Done()
	}()

	// Wait for the signal handling goroutine to finish
	wg.Wait()
	log.Println("Coordinator shut down gracefully")
}
