package frost_dkg_multisig

import (
	"context"
	"google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"

	pb "tee-dao/rpc"
)

type SignatureService struct {
	pb.UnimplementedSignatureServer
	participant *Participant
}

func (s *SignatureService) GetPubKey(_ context.Context, in *pb.GetPubKeyRequest) (*pb.GetPubKeyReply, error) {
	if !s.participant.dkgCompleted {
		return &pb.GetPubKeyReply{
			Success:        false,
			GroupPublicKey: nil,
		}, status.Errorf(codes.FailedPrecondition, "DKG not completed")
	}

	return &pb.GetPubKeyReply{
		Success:        true,
		GroupPublicKey: s.participant.keypair.PublicKeys.GroupPublicKey[:],
	}, nil
}


func (s *SignatureService) GetSignature(_ context.Context, in *pb.GetSignatureRequest) (*pb.GetSignatureReply, error) {
	if !s.participant.readyForInitPreprocessing {
		return &pb.GetSignatureReply{
			Success:        false,
			Signature: nil,
		}, status.Errorf(codes.FailedPrecondition, "participant is not ready for signing")
	}
	s.participant.initiatePreprocessing(in.Msg)
	s.participant.logger.Info("Start waiting for signature generation")
	defer s.participant.logger.Info("Stopped waiting for signature")

	for {
		select {
		case <-s.participant.ctx.Done():
			return &pb.GetSignatureReply{
				Success:        false,
				Signature: nil,
			}, status.Errorf(codes.FailedPrecondition, "context cancelled")
		case signature := <-s.participant.signatureChan:
			if len(signature) != 64 {
				return &pb.GetSignatureReply{
					Success:        false,
					Signature: nil,
				}, status.Errorf(codes.FailedPrecondition, "signature size mismatch: %d bytes", len(signature))
			}
			return &pb.GetSignatureReply{
				Success:        true,
				Signature: signature,
			}, nil
		}
	}
}
