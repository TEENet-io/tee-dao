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
	// check if the client is already attested
	if _, ok := s.coordinator.attestationServer.AttestedServers.Load(in.ParticipantConfig.Name); !ok {
		// wait for the server being added to attestedServers
		s.coordinator.waitForClientBeAttested(in.ParticipantConfig.Name)
	}

	result := s.coordinator.getNodesConfig(in.ParticipantConfig)
	if !result {
		return &pb.GetConfigReply{
			Success:            false,
			Threshold:          0,
			Leader:             "",
			ParticipantConfigs: nil,
		}, errors.New("failed to get nodes config")
	}

	s.coordinator.logger.Info("Start waiting for configs")
	defer s.coordinator.logger.Info("Stopped waiting for configs")

	s.coordinator.configCond.L.Lock()
	for countSyncMapElements(&s.coordinator.participantConfigs) < s.coordinator.config.NodesNum {
		s.coordinator.logger.With("func", "GetConfig").Debug("Waiting for all nodes to send their configs, current count", "currentCount", countSyncMapElements(&s.coordinator.participantConfigs))
		s.coordinator.configCond.Wait()
	}
	s.coordinator.configCond.L.Unlock()

	participantConfigsMap := make(map[int32]*pb.NodeConfig)
	s.coordinator.participantConfigs.Range(func(key, value interface{}) bool {
		participantConfigsMap[key.(int32)] = value.(*pb.NodeConfig)
		return true
	})

	return &pb.GetConfigReply{
		Success:            true,
		Threshold:          int32(s.coordinator.config.Threshold),
		Leader:             s.coordinator.Leader,
		ParticipantConfigs: participantConfigsMap,
	}, nil
}
