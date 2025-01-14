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
	// check if the client is already attested
	if _, ok := s.participant.attestationServer.AttestedServers.Load(in.UserName); !ok {
		// wait for the server being added to attestedServers
		s.participant.waitForClientBeAttested(in.UserName)
	}

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
	// check if the client is already attested
	if _, ok := s.participant.attestationServer.AttestedServers.Load(in.UserName); !ok {
		// wait for the server being added to attestedServers
		s.participant.waitForClientBeAttested(in.UserName)
	}
	if !s.participant.readyForInitPreprocessing {
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("not ready for signature generation")
	}

	// Create a new request
	request := &Request{
		Message:  in.Msg,
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
			}, errors.New("invalid signature length")
		}
		return &pb.GetSignatureReply{
			Success:   true,
			Signature: signature,
		}, nil
	case <-time.After(5 * time.Minute): // Timeout after 30 seconds
		return &pb.GetSignatureReply{
			Success:   false,
			Signature: nil,
		}, errors.New("signature generation timeout")
	}
}
