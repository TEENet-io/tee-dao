package coordinator

import (
	"context"
	"errors"

	pb "tee-dao/rpc"
)

type CoordinatorService struct {
	pb.UnimplementedCoordinatorServer
	coordinator *Coordinator
}


func (s *CoordinatorService) GetConfig(_ context.Context, in *pb.GetConfigRequest) (*pb.GetConfigReply, error) {
	result := s.coordinator.getNodesConfig(in.ParticipantConfig)
	if !result {
		return &pb.GetConfigReply{
			Success:        false,
			Threshold:      0,
			Leader:         "",
			ParticipantConfigs: nil,
		}, errors.New("Failed to get nodes config")
	}

	s.coordinator.logger.Info("Start waiting for configs")
	defer s.coordinator.logger.Info("Stopped waiting for configs")

	s.coordinator.configCond.L.Lock()
	for len(s.coordinator.participantConfigs) < s.coordinator.config.NodesNum {
		s.coordinator.configCond.Wait()
	}
	s.coordinator.configCond.L.Unlock()

	return &pb.GetConfigReply{
		Success:            true,
		Threshold:          int32(s.coordinator.config.Threshold),
		Leader:             s.coordinator.Leader,
		ParticipantConfigs: s.coordinator.participantConfigs,
	}, nil
}
