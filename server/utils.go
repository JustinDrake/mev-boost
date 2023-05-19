package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/attestantio/go-builder-client/api"
	apibealltrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apicapella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apideneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost/config"
	"github.com/sirupsen/logrus"
)

var (
	errHTTPErrorResponse  = errors.New("HTTP error response")
	errInvalidForkVersion = errors.New("invalid fork version")
	errInvalidTransaction = errors.New("invalid transaction")
	errMaxRetriesExceeded = errors.New("max retries exceeded")
)

// UserAgent is a custom string type to avoid confusing url + userAgent parameters in SendHTTPRequest
type UserAgent string

// BlockHashHex is a hex-string representation of a block hash
type BlockHashHex string

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set headers
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, userAgent)))

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// SendHTTPRequestWithRetries - prepare and send HTTP request, retrying the request if within the client timeout
func SendHTTPRequestWithRetries(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, payload, dst any, maxRetries int, log *logrus.Entry) (code int, err error) {
	var requestCtx context.Context
	var cancel context.CancelFunc
	if client.Timeout > 0 {
		// Create a context with a timeout as configured in the http client
		requestCtx, cancel = context.WithTimeout(context.Background(), client.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	attempts := 0
	for {
		attempts++
		if requestCtx.Err() != nil {
			return 0, fmt.Errorf("request context error after %d attempts: %w", attempts, requestCtx.Err())
		}
		if attempts > maxRetries {
			return 0, errMaxRetriesExceeded
		}

		code, err = SendHTTPRequest(ctx, client, method, url, userAgent, payload, dst)
		if err != nil {
			log.WithError(err).Warn("error making request to relay, retrying")
			time.Sleep(100 * time.Millisecond) // note: this timeout is only applied between retries, it does not delay the initial request!
			continue
		}
		return code, nil
	}
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType boostTypes.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain boostTypes.Domain, err error) {
	genesisValidatorsRoot := boostTypes.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, errInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return boostTypes.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into a struct
func DecodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

// GetURI returns the full request URI with scheme, host, path and args.
func GetURI(url *url.URL, path string) string {
	u2 := *url
	u2.User = nil
	u2.Path = path
	return u2.String()
}

// bidResp are entries in the bids cache
type bidResp struct {
	t         time.Time
	response  GetHeaderResponse
	blockHash string
	relays    []RelayEntry
}

// bidRespKey is used as key for the bids cache
type bidRespKey struct {
	slot      uint64
	blockHash string
}

func httpClientDisallowRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func weiBigIntToEthBigFloat(wei *big.Int) (ethValue *big.Float) {
	// wei / 10^18
	fbalance := new(big.Float)
	fbalance.SetString(wei.String())
	ethValue = new(big.Float).Quo(fbalance, big.NewFloat(1e18))
	return
}

func ComputeBlockHash(payload *api.VersionedExecutionPayload) (phase0.Hash32, error) {
	header, err := executionPayloadToBlockHeader(payload)
	if err != nil {
		return phase0.Hash32{}, err
	}
	return phase0.Hash32(header.Hash()), nil
}

func executionPayloadToBlockHeader(payload *api.VersionedExecutionPayload) (*types.Header, error) {
	switch payload.Version {
	case consensusspec.DataVersionBellatrix:
		transactionHash, err := deriveTransactionsHash(payload.Bellatrix.Transactions)
		if err != nil {
			return nil, err
		}
		baseFeePerGas := deriveBaseFeePerGas(payload.Bellatrix.BaseFeePerGas)
		return &types.Header{
			ParentHash:  common.Hash(payload.Bellatrix.ParentHash),
			UncleHash:   types.EmptyUncleHash,
			Coinbase:    common.Address(payload.Bellatrix.FeeRecipient),
			Root:        common.Hash(payload.Bellatrix.StateRoot),
			TxHash:      transactionHash,
			ReceiptHash: common.Hash(payload.Bellatrix.ReceiptsRoot),
			Bloom:       types.Bloom(payload.Bellatrix.LogsBloom),
			Difficulty:  common.Big0,
			Number:      new(big.Int).SetUint64(payload.Bellatrix.BlockNumber),
			GasLimit:    payload.Bellatrix.GasLimit,
			GasUsed:     payload.Bellatrix.GasUsed,
			Time:        payload.Bellatrix.Timestamp,
			Extra:       payload.Bellatrix.ExtraData,
			MixDigest:   common.Hash(payload.Bellatrix.PrevRandao),
			BaseFee:     baseFeePerGas,
		}, nil
	case consensusspec.DataVersionCapella:
		transactionHash, err := deriveTransactionsHash(payload.Capella.Transactions)
		if err != nil {
			return nil, err
		}
		withdrawalsHash := deriveWithdrawalsHash(payload.Capella.Withdrawals)
		baseFeePerGas := deriveBaseFeePerGas(payload.Capella.BaseFeePerGas)
		return &types.Header{
			ParentHash:      common.Hash(payload.Capella.ParentHash),
			UncleHash:       types.EmptyUncleHash,
			Coinbase:        common.Address(payload.Capella.FeeRecipient),
			Root:            common.Hash(payload.Capella.StateRoot),
			TxHash:          transactionHash,
			ReceiptHash:     common.Hash(payload.Capella.ReceiptsRoot),
			Bloom:           types.Bloom(payload.Capella.LogsBloom),
			Difficulty:      common.Big0,
			Number:          new(big.Int).SetUint64(payload.Capella.BlockNumber),
			GasLimit:        payload.Capella.GasLimit,
			GasUsed:         payload.Capella.GasUsed,
			Time:            payload.Capella.Timestamp,
			Extra:           payload.Capella.ExtraData,
			MixDigest:       common.Hash(payload.Capella.PrevRandao),
			BaseFee:         baseFeePerGas,
			WithdrawalsHash: &withdrawalsHash,
		}, nil
	case consensusspec.DataVersionDeneb:
		transactionHash, err := deriveTransactionsHash(payload.Deneb.Transactions)
		if err != nil {
			return nil, err
		}
		baseFeePerGas := payload.Deneb.BaseFeePerGas.ToBig()
		withdrawalsHash := deriveWithdrawalsHash(payload.Deneb.Withdrawals)
		return &types.Header{
			ParentHash:      common.Hash(payload.Deneb.ParentHash),
			UncleHash:       types.EmptyUncleHash,
			Coinbase:        common.Address(payload.Deneb.FeeRecipient),
			Root:            common.Hash(payload.Deneb.StateRoot),
			TxHash:          transactionHash,
			ReceiptHash:     common.Hash(payload.Deneb.ReceiptsRoot),
			Bloom:           types.Bloom(payload.Deneb.LogsBloom),
			Difficulty:      common.Big0,
			Number:          new(big.Int).SetUint64(payload.Deneb.BlockNumber),
			GasLimit:        payload.Deneb.GasLimit,
			GasUsed:         payload.Deneb.GasUsed,
			Time:            payload.Deneb.Timestamp,
			Extra:           payload.Deneb.ExtraData,
			MixDigest:       common.Hash(payload.Deneb.PrevRandao),
			BaseFee:         baseFeePerGas,
			WithdrawalsHash: &withdrawalsHash,
			ExcessDataGas:   payload.Deneb.ExcessDataGas.ToBig(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported data version %d", payload.Version)
	}
}

func deriveTransactionsHash(transactions []bellatrix.Transaction) (common.Hash, error) {
	transactionData := make([]*types.Transaction, len(transactions))
	for i, encTx := range transactions {
		var tx types.Transaction

		if err := tx.UnmarshalBinary(encTx); err != nil {
			return common.Hash{}, errInvalidTransaction
		}
		transactionData[i] = &tx
	}
	return types.DeriveSha(types.Transactions(transactionData), trie.NewStackTrie(nil)), nil
}

func deriveWithdrawalsHash(withdrawals []*capella.Withdrawal) common.Hash {
	withdrawalData := make([]*types.Withdrawal, len(withdrawals))
	for i, w := range withdrawals {
		withdrawalData[i] = &types.Withdrawal{
			Index:     uint64(w.Index),
			Validator: uint64(w.ValidatorIndex),
			Address:   common.Address(w.Address),
			Amount:    uint64(w.Amount),
		}
	}
	return types.DeriveSha(types.Withdrawals(withdrawalData), trie.NewStackTrie(nil))
}

func deriveBaseFeePerGas(baseFeePerGas [32]byte) *big.Int {
	// base fee per gas is stored little-endian but we need it
	// big-endian for big.Int.
	var arr [32]byte
	for i := 0; i < 32; i++ {
		arr[i] = baseFeePerGas[32-1-i]
	}
	return new(big.Int).SetBytes(arr[:])
}

func decodeSignedBlindedBeaconBlock(body []byte, consensusVersion string) (*SignedBlindedBeaconBlock, error) {
	payload := new(SignedBlindedBeaconBlock)

	switch consensusVersion {
	case "bellatrix":
		bellatrix := new(apibealltrix.SignedBlindedBeaconBlock)
		if err := DecodeJSON(bytes.NewReader(body), bellatrix); err != nil {
			return nil, err
		}
		payload.Bellatrix = bellatrix
	case "capella":
		capella := new(apicapella.SignedBlindedBeaconBlock)
		if err := DecodeJSON(bytes.NewReader(body), capella); err != nil {
			return nil, err
		}
		payload.Capella = capella
	case "deneb":
		deneb := new(apideneb.SignedBlindedBeaconBlock)
		if err := DecodeJSON(bytes.NewReader(body), deneb); err != nil {
			return nil, err
		}
		payload.Deneb = deneb
	default:
		// header is optional, so we try to decode into all types
		if err := DecodeJSON(bytes.NewReader(body), payload); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func isEmptyPayload(payload *api.VersionedExecutionPayload) bool {
	if payload.IsEmpty() {
		return true
	}
	blockHash, err := payload.BlockHash()
	if err != nil {
		// parts of payload is missing
		return true
	}
	return blockHash == nilHash
}
