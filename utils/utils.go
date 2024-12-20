package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"log"
	"tee-dao/coordinator"
	pb "tee-dao/rpc"
)

// LoadNodeConfig loads a node-specific configuration file and returns a Config struct.
func LoadNodeConfig(filePath string) (*pb.NodeConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open node config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read node config file: %v", err)
	}
	// log.Printf("Node config data: %v", data)

	var nodeConfig pb.NodeConfig
	err = json.Unmarshal(data, &nodeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node config JSON: %v", err)
	}

	log.Printf("Node config: %v", nodeConfig)
	return &nodeConfig, nil
}

// LoadCoordinatorConfig loads the coordinator configuration file and returns a CoordinatorConfig struct.
func LoadCoordinatorConfig(filePath string) (*coordinator.CoordinatorConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open coordinator config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read coordinator config file: %v", err)
	}

	var coordinatorConfig coordinator.CoordinatorConfig
	err = json.Unmarshal(data, &coordinatorConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse coordinator config JSON: %v", err)
	}

	return &coordinatorConfig, nil
}
