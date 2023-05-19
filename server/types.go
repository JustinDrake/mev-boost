package server

import (
	"encoding/json"
	"errors"
	"math/big"

	apicapella "github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	"github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/types"
)

var (
	errNoResponse = errors.New("no response")
	errNilStruct  = errors.New("nil struct")
	errNoData     = errors.New("no data")
	errNoMessage  = errors.New("no message")
	errNoBody     = errors.New("no body")
	errNoHeader   = errors.New("no header")
)

// wrapper different for types
type GetHeaderResponse struct {
	Bellatrix *types.GetHeaderResponse
	Capella   *spec.VersionedSignedBuilderBid
}

func (r *GetHeaderResponse) UnmarshalJSON(data []byte) error {
	var err error

	var capella spec.VersionedSignedBuilderBid
	err = json.Unmarshal(data, &capella)
	if err == nil && capella.Capella != nil {
		r.Capella = &capella
		return nil
	}

	var bellatrix types.GetHeaderResponse
	err = json.Unmarshal(data, &bellatrix)
	if err != nil {
		return err
	}

	r.Bellatrix = &bellatrix

	return nil
}

func (r *GetHeaderResponse) MarshalJSON() ([]byte, error) {
	if r.Capella != nil {
		return json.Marshal(r.Capella)
	}

	if r.Bellatrix != nil {
		return json.Marshal(r.Bellatrix)
	}

	return nil, errNoResponse
}

func (r *GetHeaderResponse) IsInvalid() bool {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data == nil || r.Bellatrix.Data.Message == nil || r.Bellatrix.Data.Message.Header == nil || r.Bellatrix.Data.Message.Header.BlockHash == types.Hash(nilHash)
	}

	if r.Capella != nil {
		return r.Capella.Capella == nil || r.Capella.Capella.Message == nil || r.Capella.Capella.Message.Header == nil || r.Capella.Capella.Message.Header.BlockHash == nilHash
	}

	return true
}

func (r *GetHeaderResponse) BlockHash() string {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Header.BlockHash.String()
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Header.BlockHash.String()
	}

	return ""
}

func (r *GetHeaderResponse) Value() *big.Int {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Value.BigInt()
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Value.ToBig()
	}

	return nil
}

func (r *GetHeaderResponse) BlockNumber() uint64 {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Header.BlockNumber
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Header.BlockNumber
	}

	return 0
}

func (r *GetHeaderResponse) TransactionsRoot() string {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Header.TransactionsRoot.String()
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Header.TransactionsRoot.String()
	}

	return ""
}

func (r *GetHeaderResponse) Pubkey() string {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Pubkey.String()
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Pubkey.String()
	}

	return ""
}

func (r *GetHeaderResponse) Signature() []byte {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Signature[:]
	}

	if r.Capella != nil {
		return r.Capella.Capella.Signature[:]
	}

	return nil
}

func (r *GetHeaderResponse) Message() types.HashTreeRoot {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message
	}

	return nil
}

func (r *GetHeaderResponse) ParentHash() string {
	if r.Bellatrix != nil {
		return r.Bellatrix.Data.Message.Header.ParentHash.String()
	}

	if r.Capella != nil {
		return r.Capella.Capella.Message.Header.ParentHash.String()
	}

	return ""
}

func (r *GetHeaderResponse) IsEmpty() bool {
	return r.Bellatrix == nil && r.Capella == nil
}

func (r *GetHeaderResponse) BuilderBid() *SignedBuilderBid {
	if r.Bellatrix != nil {
		return &SignedBuilderBid{Bellatrix: r.Bellatrix.Data}
	}
	if r.Capella != nil {
		return &SignedBuilderBid{Capella: r.Capella.Capella}
	}
	return nil
}

type SignedBuilderBid struct {
	Bellatrix *types.SignedBuilderBid
	Capella   *apicapella.SignedBuilderBid
}

func (r *SignedBuilderBid) UnmarshalJSON(data []byte) error {
	var err error
	var bellatrix types.SignedBuilderBid
	err = json.Unmarshal(data, &bellatrix)
	if err == nil {
		r.Bellatrix = &bellatrix
		return nil
	}

	var capella apicapella.SignedBuilderBid
	err = json.Unmarshal(data, &capella)
	if err != nil {
		return err
	}

	r.Capella = &capella
	return nil
}

func (r *SignedBuilderBid) MarshalJSON() ([]byte, error) {
	if r.Bellatrix != nil {
		return json.Marshal(r.Bellatrix)
	}

	if r.Capella != nil {
		return json.Marshal(r.Capella)
	}

	return nil, errNoResponse
}

type SignedBlindedBeaconBlock struct {
	Bellatrix *bellatrix.SignedBlindedBeaconBlock
	Capella   *capella.SignedBlindedBeaconBlock
	Deneb     *deneb.SignedBlindedBeaconBlock
}

func (s *SignedBlindedBeaconBlock) UnmarshalJSON(data []byte) error {
	var err error
	var bellatrix bellatrix.SignedBlindedBeaconBlock
	err = json.Unmarshal(data, &bellatrix)
	if err == nil {
		s.Bellatrix = &bellatrix
		return nil
	}

	var capella capella.SignedBlindedBeaconBlock
	err = json.Unmarshal(data, &capella)
	if err == nil {
		s.Capella = &capella
		return nil
	}

	var deneb deneb.SignedBlindedBeaconBlock
	err = json.Unmarshal(data, &deneb)
	if err != nil {
		return err
	}
	s.Deneb = &deneb

	return nil
}

func (s *SignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}

	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}

	if s.Deneb != nil {
		return json.Marshal(s.Deneb)
	}

	return nil, errNoResponse
}

func (s *SignedBlindedBeaconBlock) IsEmpty() bool {
	if s.Bellatrix != nil {
		return s.Bellatrix.Message == nil || s.Bellatrix.Message.Body == nil || s.Bellatrix.Message.Body.ExecutionPayloadHeader == nil
	}
	if s.Capella != nil {
		return s.Capella.Message == nil || s.Capella.Message.Body == nil || s.Capella.Message.Body.ExecutionPayloadHeader == nil
	}
	if s.Deneb != nil {
		return s.Deneb.Message == nil || s.Deneb.Message.Body == nil || s.Deneb.Message.Body.ExecutionPayloadHeader == nil
	}
	return true
}

func (s *SignedBlindedBeaconBlock) Slot() (phase0.Slot, error) {
	if s == nil {
		return 0, errNoData
	}
	if s.Bellatrix != nil {
		if s.Bellatrix.Message == nil {
			return 0, errNoMessage
		}
		return s.Bellatrix.Message.Slot, nil
	}
	if s.Capella != nil {
		if s.Capella.Message == nil {
			return 0, errNoMessage
		}
		return s.Capella.Message.Slot, nil
	}
	if s.Deneb != nil {
		if s.Deneb.Message == nil {
			return 0, errNoMessage
		}
		return s.Deneb.Message.Slot, nil
	}
	return 0, errNoData
}

func (s *SignedBlindedBeaconBlock) BlockHash() (phase0.Hash32, error) {
	if s == nil {
		return phase0.Hash32{}, errNoData
	}
	if s.Bellatrix != nil {
		if s.Bellatrix.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Bellatrix.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Bellatrix.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	}
	if s.Capella != nil {
		if s.Capella.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Capella.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Capella.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	}
	if s.Deneb != nil {
		if s.Deneb.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Deneb.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Deneb.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Deneb.Message.Body.ExecutionPayloadHeader.BlockHash, nil
	}
	return phase0.Hash32{}, errNoData
}

func (s *SignedBlindedBeaconBlock) ParentHash() (phase0.Hash32, error) {
	if s == nil {
		return phase0.Hash32{}, errNoData
	}
	if s.Bellatrix != nil {
		if s.Bellatrix.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Bellatrix.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Bellatrix.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.ParentHash, nil
	}
	if s.Capella != nil {
		if s.Capella.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Capella.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Capella.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Capella.Message.Body.ExecutionPayloadHeader.ParentHash, nil
	}
	if s.Deneb != nil {
		if s.Deneb.Message == nil {
			return phase0.Hash32{}, errNoMessage
		}
		if s.Deneb.Message.Body == nil {
			return phase0.Hash32{}, errNoBody
		}
		if s.Deneb.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, errNoHeader
		}
		return s.Deneb.Message.Body.ExecutionPayloadHeader.ParentHash, nil
	}
	return phase0.Hash32{}, errNoData
}
