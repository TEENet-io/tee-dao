package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"tee-dao/comm"
)

// GeneralConfig holds the structure for loading config.json
type GeneralConfig struct {
	Leader       string              `json:"leader"`
	Threshold    int                 `json:"threshold"`
	Participants []comm.PeerConfig   `json:"participants"`
	Clients      []comm.ClientConfig `json:"clients"`
}

// LoadGeneralConfig reads the general configuration file and returns the leader's name, participant count, minimum signer count, and peers list.
func LoadGeneralConfig(filePath string) (string, int, int, []comm.PeerConfig, []comm.ClientConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var generalConfig GeneralConfig
	err = json.Unmarshal(data, &generalConfig)
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("failed to parse config JSON: %v", err)
	}

	leader := generalConfig.Leader
	minSignerCount := generalConfig.Threshold
	numParticipants := len(generalConfig.Participants)

	return leader, numParticipants, minSignerCount, generalConfig.Participants, generalConfig.Clients, nil
}

// LoadNodeConfig loads a node-specific configuration file and returns a Config struct.
func LoadNodeConfig(filePath string) (*comm.Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open node config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read node config file: %v", err)
	}

	var nodeConfig comm.Config
	err = json.Unmarshal(data, &nodeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node config JSON: %v", err)
	}

	return &nodeConfig, nil
}
