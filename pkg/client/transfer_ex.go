package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
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

var zero32Bytes = "0000000000000000000000000000000000000000000000000000000000000000"

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

// Trc20Transfer is TRC20 transfer to token to address, to replace trc20.go TRC20Send
func (g *GrpcClient) Trc20Transfer(fromKey *ecdsa.PrivateKey, toAddress, contractAddress string, amount *big.Int, feeLimit int64) (string, error) {
	addrB, err := address.Base58ToAddress(toAddress)
	if err != nil {
		return "", err
	}
	ab := common.LeftPadBytes(amount.Bytes(), 32)
	req := trc20TransferMethodSignature + zero32Bytes[len(addrB.Hex())-4:] + addrB.Hex()[4:]
	req += common.Bytes2Hex(ab)

	data, _ := hexutil.Decode(req)
	return g.callContractEx(fromKey, contractAddress, data, feeLimit)
}

// Trc20Approve is TRC20 approve to token to address, to replace trc20.go TRC20Approve
func (g *GrpcClient) Trc20Approve(fromKey *ecdsa.PrivateKey, spenderAddress, contractAddress string, amount *big.Int, feeLimit int64) (string, error) {
	addrB, err := address.Base58ToAddress(spenderAddress)
	if err != nil {
		return "", err
	}
	ab := common.LeftPadBytes(amount.Bytes(), 32)
	req := trc20TransferFromSignature + zero32Bytes[len(addrB.Hex())-4:] + addrB.Hex()[4:]
	req += common.Bytes2Hex(ab)

	data, _ := hexutil.Decode(req)
	return g.callContractEx(fromKey, contractAddress, data, feeLimit)
}

// Trc20TransferFrom is TRC20  transferFrom(address sender, address recipient, uint256 amount)
func (g *GrpcClient) Trc20TransferFrom(spenderKey *ecdsa.PrivateKey, ownerAddress, toAddress, contractAddress string, amount *big.Int, feeLimit int64) (string, error) {
	owner, err := address.Base58ToAddress(ownerAddress)
	if err != nil {
		return "", err
	}

	toAddr, err := address.Base58ToAddress(toAddress)
	if err != nil {
		return "", err
	}

	ab := common.LeftPadBytes(amount.Bytes(), 32)
	req := trc20ApproveMethodSignature
	req += zero32Bytes[len(owner.Hex())-4:] + owner.Hex()[4:]   // owner(sender)
	req += zero32Bytes[len(toAddr.Hex())-4:] + toAddr.Hex()[4:] // to (recipient)
	req += common.Bytes2Hex(ab)

	data, _ := hexutil.Decode(req)
	return g.callContractEx(spenderKey, contractAddress, data, feeLimit)
}

// callContractEx call TRC20 contract , it's a wrapper of contract.go TriggerConstantContract,
func (g *GrpcClient) callContractEx(senderKey *ecdsa.PrivateKey, contractAddress string, data []byte, feeLimit int64) (string, error) {
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
