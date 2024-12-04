package coordinator

import (
	"context"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	pb "tee-dao/rpc"
)

type ConfigService struct {
	pb.UnimplementedConfigServer
	coordinator *Coordinator
}


func (c *ConfigService) GetConfig(_ context.Context, in *pb.GetConfigRequest) (*pb.GetConfigReply, error) {
	result := c.coordinator.getNodesConfig(in.ParticipantConfig)
	if !result {
		return &pb.GetConfigReply{
			Success:        false,
			Threshold:      0,
			Leader:         "",
			ParticipantConfigs: nil,
		}, status.Errorf(codes.FailedPrecondition, "Failed to get nodes config")
	}

	c.coordinator.logger.Info("Start waiting for configs")
	defer c.coordinator.logger.Info("Stopped waiting for configs")

	c.coordinator.configCond.L.Lock()
	for len(c.coordinator.participantConfigs) < c.coordinator.config.NodesNum {
		c.coordinator.configCond.Wait()
	}
	c.coordinator.configCond.L.Unlock()

	return &pb.GetConfigReply{
		Success:            true,
		Threshold:          int32(c.coordinator.config.Threshold),
		Leader:             c.coordinator.Leader,
		ParticipantConfigs: c.coordinator.participantConfigs,
	}, nil
}
