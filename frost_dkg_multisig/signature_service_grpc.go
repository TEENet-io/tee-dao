package frost_dkg_multisig

import (
	"context"
	"errors"
	"sync"
	"time"

	pb "tee-dao/rpc"
)

type SignatureService struct {
	pb.UnimplementedSignatureServer
	participant *Participant
	wg          sync.WaitGroup
}

func (s *SignatureService) GetPubKey(_ context.Context, in *pb.GetPubKeyRequest) (*pb.GetPubKeyReply, error) {
	if !s.participant.dkgCompleted {
		return &pb.GetPubKeyReply{
			Success:        false,
			GroupPublicKey: nil,
		}, errors.New("DKG not completed")
	}

	return &pb.GetPubKeyReply{
		Success:        true,
		GroupPublicKey: s.participant.keypair.PublicKeys.GroupPublicKey[:],
	}, nil
}

func (s *SignatureService) GetSignature(_ context.Context, in *pb.GetSignatureRequest) (*pb.GetSignatureReply, error) {
	if !s.participant.readyForInitPreprocessing {
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("not ready for signature generation")
	}

	// Create a new request
	if len(in.Msg) != 32 {
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("invalid msg hash length")
	}

	request := &Request{
		Message:  [32]byte(in.Msg),
		Response: make(chan []byte),
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.participant.HandleRequest(request)
	}()

	s.participant.logger.Info("Start waiting for signature generation")
	defer s.participant.logger.Info("Stopped waiting for signature")

	select {
	case <-s.participant.ctx.Done():
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("context cancelled")
	case signature := <-request.Response:
		if len(signature) != 64 {
			return &pb.GetSignatureReply{
				Success:   false,
				Signature: nil,
			}, errors.New("fail to sign, invalid signature length")
		}
		return &pb.GetSignatureReply{
			Success:   true,
			Signature: signature,
		}, nil
	case <-time.After(1 * time.Minute): // Timeout after 1 minute
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("signature generation timeout")
	}
}
