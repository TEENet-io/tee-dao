package coordinator

import (
	"fmt"
	"tee-dao/frost_dkg_multisig"
)

type ConfigService struct {
	coordinator *Coordinator
}

type GetConfigArgs struct {
	ParticipantConfig frost_dkg_multisig.NodeConfig
}

type ConfigReply struct {
	Success            bool
	Threshold          int                                    // Threshold for DKG and multisig
	Leader             string                                 // Leader name
	ParticipantConfigs map[int]*frost_dkg_multisig.NodeConfig // Participant configurations
}

func (c *ConfigService) GetConfig(args *GetConfigArgs, reply *ConfigReply) error {
	result := c.coordinator.getNodesConfig(args.ParticipantConfig)
	if !result {
		reply.Success = false
		return fmt.Errorf("error in receive node config")
	}

	c.coordinator.logger.Info("Start waiting for configs")
	defer c.coordinator.logger.Info("Stopped waiting for configs")

	c.coordinator.configCond.L.Lock()
	for len(c.coordinator.participantConfigs) < c.coordinator.config.NodesNum {
		c.coordinator.configCond.Wait()
	}
	c.coordinator.configCond.L.Unlock()

	reply.Success = true
	reply.Threshold = c.coordinator.config.Threshold
	reply.Leader = c.coordinator.Leader
	reply.ParticipantConfigs = c.coordinator.participantConfigs
	return nil
}
