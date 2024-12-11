package comm

import (
	"context"

	pb "tee-dao/rpc"
)

type NodeCommService struct {
	pb.UnimplementedNodeCommServer
	Communicator *Communicator
}

func (s *NodeCommService) RequestHandler(_ context.Context, in *pb.NodeMsg) (*pb.NodeReply, error) {
	err := s.Communicator.handleMessage(*in)
	if err != nil {
		return &pb.NodeReply{Success: false}, err
	}
	
	return &pb.NodeReply{Success: true}, nil
}