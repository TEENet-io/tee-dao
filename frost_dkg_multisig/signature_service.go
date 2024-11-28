package frost_dkg_multisig

import "fmt"

type SignatureService struct {
	participant *Participant
}

type GetPubKeyArgs struct {
	UserID int
}

type PubKeyReply struct {
	Success        bool
	GroupPublicKey [64]byte
}

func (s *SignatureService) GetPubKey(args *GetPubKeyArgs, reply *PubKeyReply) error {
	if !s.participant.DKGCompleted {
		reply.Success = false
		return fmt.Errorf("DKG not completed")
	}
	reply.Success = true
	reply.GroupPublicKey = s.participant.Keypair.PublicKeys.GroupPublicKey
	return nil
}

type SignArgs struct {
	Msg []byte
}

type SignatureReply struct {
	Success   bool
	Signature [64]byte
}

func (s *SignatureService) Sign(args *SignArgs, reply *SignatureReply) error {
	if !s.participant.ReadyForInitPreprocessing {
		reply.Success = false
		return fmt.Errorf("participant is not ready for signing")
	}
	s.participant.initiatePreprocessing(args.Msg)
	s.participant.logger.Info("Start waiting for signature generation")
	defer s.participant.logger.Info("Stopped waiting for signature")

	for {
		select {
		case <-s.participant.ctx.Done():
			reply.Success = false
			return fmt.Errorf("context cancelled")
		case signature := <-s.participant.SignatureChan:
			if len(signature) != 64 {
				return fmt.Errorf("signature size mismatch: %d bytes", len(signature))
			}
			reply.Success = true
			reply.Signature = [64]byte(signature)
			return nil
		}
	}
}
