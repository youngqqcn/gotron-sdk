package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/common"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"google.golang.org/protobuf/proto"
)

// create by yqq 2023-04-25

// refactor: https://github.com/youngqqcn/tron-rpc/blob/main/service/client.go

// TransferEx  for TRX transfer, it's a refactor Transfer of transfer.go
func (g *GrpcClient) TransferEx(senderKey *ecdsa.PrivateKey, toAddress string, amount int64) (string, error) {
	var err error
	var txid string

	transferContract := new(core.TransferContract)
	transferContract.OwnerAddress = address.PubkeyToAddress(senderKey.PublicKey).Bytes()
	transferContract.ToAddress, err = common.DecodeCheck(toAddress)
	if err != nil {
		return txid, err
	}

	transferContract.Amount = amount

	// timeout is 30 secs
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(30))
	defer cancel()

	transferTransactionEx, err := g.Client.CreateTransaction2(ctx, transferContract)
	if err != nil {
		return txid, err
	}

	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil ||
		len(transferTransaction.GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	hash, err := SignTransaction(transferTransaction, senderKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := g.Client.BroadcastTransaction(ctx, transferTransaction)
	if err != nil {
		// no return txid for failed tx
		return "", err
	}
	if !result.Result {
		// no return txid for failed tx
		return "", fmt.Errorf("api get false the msg: %s", result.String())
	}
	return txid, err
}

// TransferAssetEx  for TRC10 transfer, it's a refactor  TransferAsset of assets.go ,
func (g *GrpcClient) TransferAssetEx(senderKey *ecdsa.PrivateKey, AssetName, toAddress string, amount int64) (string, error) {
	var err error
	var txid string

	transferContract := new(core.TransferAssetContract)
	transferContract.OwnerAddress = address.PubkeyToAddress(senderKey.PublicKey).Bytes()
	transferContract.ToAddress, err = common.DecodeCheck(toAddress)
	if err != nil {
		return txid, err
	}

	transferContract.AssetName, err = common.DecodeCheck(AssetName)
	if err != nil {
		return txid, err
	}

	transferContract.Amount = amount

	// timeout is 30 secs
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(30))
	defer cancel()

	transferTransactionEx, err := g.Client.TransferAsset2(ctx, transferContract)
	if err != nil {
		return txid, err
	}

	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil ||
		len(transferTransaction.GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	hash, err := SignTransaction(transferTransaction, senderKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := g.Client.BroadcastTransaction(ctx, transferTransaction)
	if err != nil {
		// no return txid for failed tx
		return "", err
	}
	if !result.Result {
		// no return txid for failed tx
		return "", fmt.Errorf("api get false the msg: %s", result.String())
	}
	return txid, err
}

// TransferContractEx for TRC20 transfer, it's a wrapper of contract.go TriggerConstantContract,
func (g *GrpcClient) TransferContractEx(senderKey *ecdsa.PrivateKey, contractAddress string, data []byte, feeLimit int64) (string, error) {
	var err error
	var txid string

	transferContract := new(core.TriggerSmartContract)
	transferContract.OwnerAddress = address.PubkeyToAddress(senderKey.PublicKey).Bytes()
	transferContract.ContractAddress, err = common.DecodeCheck(contractAddress)
	if err != nil {
		return txid, err
	}

	transferContract.Data = data

	// timeout is 30 secs
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(30))
	defer cancel()

	transferTransactionEx, err := g.Client.TriggerConstantContract(ctx, transferContract)
	if err != nil {
		return txid, err
	}
	transferTransaction := transferTransactionEx.Transaction
	if transferTransaction == nil ||
		len(transferTransaction.GetRawData().GetContract()) == 0 {
		return txid, fmt.Errorf("transfer error: invalid transaction")
	}
	if feeLimit > 0 {
		transferTransaction.RawData.FeeLimit = feeLimit
	}

	hash, err := SignTransaction(transferTransaction, senderKey)
	if err != nil {
		return txid, err
	}
	txid = hexutil.Encode(hash)

	result, err := g.Client.BroadcastTransaction(ctx,
		transferTransaction)
	if err != nil {
		// no return txid for failed tx
		return "", err
	}
	if !result.Result {
		// no return txid for failed tx
		return "", fmt.Errorf("api get false the msg: %s", result.String())
	}
	return txid, err
}

// SignTransaction NOTE: key will be as Zero, after this function
func SignTransaction(transaction *core.Transaction, key *ecdsa.PrivateKey) ([]byte, error) {
	// for safety,
	defer zeroKey(key)

	transaction.GetRawData().Timestamp = time.Now().UnixNano() / 1000000
	rawData, err := proto.Marshal(transaction.GetRawData())
	if err != nil {
		return nil, err
	}
	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	contractList := transaction.GetRawData().GetContract()
	for range contractList {
		signature, err := crypto.Sign(hash, key)
		if err != nil {
			return nil, err
		}
		transaction.Signature = append(transaction.Signature, signature)
	}

	return hash, nil
}

// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
