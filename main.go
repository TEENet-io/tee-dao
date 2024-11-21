package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee-dao/comm"
	"tee-dao/frost_dkg_multisig"
	"tee-dao/utils"
)

func main() {
	id := flag.Int("id", 0, "ID of the participant")
	flag.Parse()
	// Step 1: Load Configurations
	leaderName, numParticipants, minSigner, allParticipants, err := utils.LoadGeneralConfig("config/config.json")
	if err != nil {
		log.Fatalf("Error loading general config: %v", err)
	}

	nodeConfig, err := utils.LoadNodeConfig(fmt.Sprintf("config/config%d.json", *id))
	if err != nil {
		log.Fatalf("Error loading node config: %v", err)
	}
	var peers []comm.PeerConfig
	for _, participant := range allParticipants {
		if participant.ID != *id {
			peers = append(peers, participant)
		}
	}
	nodeConfig.Peers = peers

	// Step 2: Role Assignment (Leader or Participant)
	isLeader := nodeConfig.Name == leaderName
	log.Printf("Node %s initialized as %s\n", nodeConfig.Name, func() string {
		if isLeader {
			return "Leader"
		}
		return "Participant"
	}())

	// Step 3: Initialize participant state and start DKG
	// Initialize context and tag
	context := []byte("example_context") // For DKG
	tag := []byte("message_tag")         // For Signature
	participant, err := frost_dkg_multisig.NewParticipant(leaderName, nodeConfig, isLeader, *id, numParticipants, minSigner, context, tag)
	if err != nil {
		log.Fatalf("Error creating participant: %v", err)
	}

	// Start the participant
	if err := participant.Start(); err != nil {
		log.Fatalf("Failed to start participant: %v", err)
	}
	defer participant.Close()

	// Set up WaitGroup and signal handling to wait until we receive a termination signal
	var wg sync.WaitGroup
	wg.Add(1)

	// Listen for OS interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		participant.Close()
		wg.Done()
	}()

	// Wait for the signal handling goroutine to finish
	wg.Wait()
	log.Println("Participant shut down gracefully")
}
