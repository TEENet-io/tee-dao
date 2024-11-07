package utils

import (
	"distributed-multisig/comm"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
)

// GeneralConfig holds the structure for loading config.json
type GeneralConfig struct {
	Leader       string            `json:"leader"`
	Participants []comm.PeerConfig `json:"participants"`
}

// LoadGeneralConfig reads the general configuration file and returns the leader's name, participant count, minimum signer count, and peers list.
func LoadGeneralConfig(filePath string) (string, int, int, []comm.PeerConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, 0, nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", 0, 0, nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var generalConfig GeneralConfig
	err = json.Unmarshal(data, &generalConfig)
	if err != nil {
		return "", 0, 0, nil, fmt.Errorf("failed to parse config JSON: %v", err)
	}

	leader := generalConfig.Leader
	numParticipants := len(generalConfig.Participants)
	minSignerCount := int(math.Ceil(float64(numParticipants) / 3.0))

	return leader, numParticipants, minSignerCount, generalConfig.Participants, nil
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
