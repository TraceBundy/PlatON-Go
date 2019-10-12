package cbft

import (
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/byzantine"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/network"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/utils"
	"github.com/PlatONnetwork/PlatON-Go/core/cbfttypes"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/crypto/bls"
	"github.com/pingcap/failpoint"
)

const (
	sendTickTime = time.Millisecond * 50
	chainID      = 120
	to           = "0x2b645d169998eb0447a21d0c48a1780d115251a9"
)

var data = []byte("100000000000000000000")

// NewBlock returns a new block for testing.
func testNewBlock(parent common.Hash, number uint64) *types.Block {
	header := &types.Header{
		Number:      big.NewInt(int64(number)),
		ParentHash:  parent,
		Time:        big.NewInt(time.Now().UnixNano()),
		Extra:       make([]byte, 77),
		ReceiptHash: common.BytesToHash(hexutil.MustDecode("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")),
		Root:        common.BytesToHash(hexutil.MustDecode("0x7fc92a727e71b48fac1da18e4b2b1b76f69edd412ed4bb4b7f7dec9acd0521f0")),
		Coinbase:    common.Address{},
		GasLimit:    10000000000,
	}
	block := types.NewBlockWithHeader(header)
	return block
}

// GenerateKeys returns the public and private key pair for testing.
func testGenerateKeys(num int) ([]*ecdsa.PrivateKey, []*bls.SecretKey) {
	pk := make([]*ecdsa.PrivateKey, 0)
	sk := make([]*bls.SecretKey, 0)

	for i := 0; i < num; i++ {
		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		ecdsaKey, _ := crypto.GenerateKey()
		pk = append(pk, ecdsaKey)
		sk = append(sk, &blsKey)
	}
	return pk, sk
}

func (cbft *Cbft) IsStartEvil() bool {
	if cbft.validatorPool == nil || cbft.state == nil || cbft.blockChain == nil {
		return false
	}
	header := cbft.blockChain.CurrentHeader()
	me, _ := cbft.validatorPool.GetValidatorByNodeID(cbft.state.Epoch(), cbft.NodeID())
	if cbft.byzantiumIndex > 1 {
		return cbft.byzantiumIndex != 0 && me.Index == cbft.byzantiumIndex && header.Number.Int64() >= 40 &&
			cbft.currentProposer().Index == me.Index
	}
	return cbft.byzantiumIndex != 0 && me.Index == cbft.byzantiumIndex && header.Number.Int64() >= 40 &&
		cbft.currentProposer().Index != me.Index
}

// GetBuildMsg use to byzantine test return byzantine msg of myself
func (cbft *Cbft) GetBuildMsg() *byzantine.MsgResult {
	if cbft.byzantium == nil {
		return nil
	}
	msg, err := cbft.byzantium.GetBuildMsg()
	if err != nil {
		return nil
	}
	return msg
}

// GetBuildMsg use to byzantine test return byzantine msg of byzantine node
func (cbft *Cbft) GetReceiveMsg() *byzantine.MsgResult {
	if cbft.byzantium == nil {
		return nil
	}
	msg, err := cbft.byzantium.GetReceiveMsg()
	if err != nil {
		return nil
	}
	return msg
}

func (cbft *Cbft) testCommitBlock(prepareBlock *protocols.PrepareBlock) {
	cbft.log.Debug("try commit block", "number", prepareBlock.BlockNum(), "hash", prepareBlock.BHash())
	cbft.state.SetHighestQCBlock(prepareBlock.Block)
	cbft.state.SetHighestLockBlock(prepareBlock.Block)
	cbft.state.SetHighestCommitBlock(prepareBlock.Block)
	// cbft.blockTree.PruneBlock(block.Hash(), block.NumberU64(), nil)
	cbft.blockTree.NewRoot(prepareBlock.Block)
	qc := &ctypes.QuorumCert{
		Epoch:        prepareBlock.Epoch,
		ViewNumber:   prepareBlock.ViewNumber,
		BlockHash:    prepareBlock.BHash(),
		BlockNumber:  prepareBlock.BlockNum(),
		BlockIndex:   prepareBlock.BlockIndex,
		Signature:    prepareBlock.Signature,
		ValidatorSet: utils.NewBitArray(32),
	}
	extra, err := ctypes.EncodeExtra(byte(cbftVersion), qc)
	if err != nil {
		cbft.log.Error("Encode extra error", "number", prepareBlock.BlockNum(), "hash", prepareBlock.BHash(), "cbftVersion", cbftVersion)
		return
	}
	cbft.log.Debug("Send consensus result to worker", "number", prepareBlock.BlockNum(), "hash", prepareBlock.BHash())
	cbft.eventMux.Post(cbfttypes.CbftResult{
		Block:              prepareBlock.Block,
		ExtraData:          extra,
		SyncState:          cbft.commitErrCh,
		ChainStateUpdateCB: func() {},
	})
}

func (cbft *Cbft) testGenerateQC(hash common.Hash, number uint64) (*ctypes.ViewChangeQuorumCert, error) {
	_, qc := cbft.blockTree.FindBlockAndQC(hash, number)
	view, err := cbft.generateViewChange(qc)
	if err != nil {
		return nil, err
	}
	viewQC, err := cbft.generateViewChangeQuorumCert(view)
	if err != nil {
		return nil, err
	}
	return viewQC, nil
}

func (cbft *Cbft) testSignBlock(block *protocols.PrepareBlock, key *bls.SecretKey, index uint32) (*protocols.PrepareVote, error) {
	prepareVote := &protocols.PrepareVote{
		Epoch:          block.Epoch,
		ViewNumber:     block.ViewNumber,
		BlockHash:      block.BHash(),
		BlockNumber:    block.BlockNum(),
		BlockIndex:     block.BlockIndex,
		ValidatorIndex: uint32(index),
	}
	buf, err := prepareVote.CannibalizeBytes()
	if err != nil {
		return nil, err
	}
	sign := key.Sign(string(buf))
	prepareVote.SetSign(sign.Serialize())
	return prepareVote, nil
}

func (cbft *Cbft) NewTransaction() (*types.Transaction, error) {
	toAddress := common.HexToAddress(to)
	signer := types.NewEIP155Signer(big.NewInt(chainID))
	amount := new(big.Int).SetUint64(10000000000000)
	gasLimit := uint64(300000000)
	key := cbft.config.Option.NodePriKey
	tx := types.NewTransaction(
		cbft.txPool.State().GetNonce(toAddress),
		toAddress,
		amount,
		gasLimit,
		cbft.txPool.GasPrice(),
		data)
	return types.SignTx(tx, signer, key)
}

func (cbft *Cbft) testLoop() {
	me, err := cbft.isCurrentValidator()
	failpoint.Inject("byzantine-VQ05-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testVQ05Loop()
		}
	})
	failpoint.Inject("byzantine-PQ05-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testPQ05Loop()
		}
	})
	failpoint.Inject("byzantine-SY01-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testSY01Loop()
		}
	})
	failpoint.Inject("byzantine-PB02-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testPB02Loop()
		}
	})
	failpoint.Inject("byzantine-PB01-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testPB01Loop()
		}
	})
	failpoint.Inject("byzantine-PB18-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.PB18 = true
			key := cbft.config.Option.NodePriKey
			setBalance, _ := new(big.Int).SetString("999999999999999999999999999999", 10)
			cbft.txPool.State().AddBalance(crypto.PubkeyToAddress(key.PublicKey), setBalance)
		}
	})
	failpoint.Inject("byzantine-VC01-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testVC01Loop()
		}
	})
	failpoint.Inject("byzantine-VC02-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testVC02Loop()
		}
	})
	failpoint.Inject("byzantine-VT01-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testVT01Loop()
		}
	})
	failpoint.Inject("byzantine-VT02-Start", func() {
		if err == nil && cbft.byzantiumIndex == me.Index {
			cbft.log.Debug("Start test send loop")
			cbft.testVT02Loop()
		}
	})
}

func (cbft *Cbft) testPB01Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err prepare block")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testPB01(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testPB01(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	prepareBlock := &protocols.PrepareBlock{
		Epoch:         cbft.state.Epoch(),
		ViewNumber:    cbft.state.ViewNumber(),
		Block:         block,
		BlockIndex:    9,
		ProposalIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(prepareBlock); err != nil {
		cbft.log.Error("Sign PrepareBlock failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareBlock); err != nil {
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareBlock); err != nil {
		return
	}
	cbft.log.Debug("Send prepare block", "block", prepareBlock.String())
	cbft.network.Broadcast(prepareBlock)
}

func (cbft *Cbft) testPB02Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err prepare block")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testPB02(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testPB02(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	prepareBlock := &protocols.PrepareBlock{
		Epoch:         cbft.state.Epoch(),
		ViewNumber:    cbft.state.ViewNumber() + i,
		Block:         block,
		BlockIndex:    2,
		ProposalIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(prepareBlock); err != nil {
		cbft.log.Error("Sign PrepareBlock failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareBlock); err != nil {
		return
	}
	cbft.log.Debug("Send prepare block", "block", prepareBlock.String())
	cbft.network.Broadcast(prepareBlock)
}

func (cbft *Cbft) testPB03Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err prepare block")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testPB03(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testPB03(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	prepareBlock := &protocols.PrepareBlock{
		Epoch:         cbft.state.Epoch() + i,
		ViewNumber:    cbft.state.ViewNumber(),
		Block:         block,
		BlockIndex:    2,
		ProposalIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(prepareBlock); err != nil {
		cbft.log.Error("Sign PrepareBlock failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareBlock); err != nil {
		return
	}
	cbft.log.Debug("Send prepare block", "block", prepareBlock.String())
	cbft.network.Broadcast(prepareBlock)
}

func (cbft *Cbft) testVT01Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err prepare vote")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testVT01(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testVT01(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	prepareVote := &protocols.PrepareVote{
		Epoch:          cbft.state.Epoch(),
		ViewNumber:     cbft.state.ViewNumber() + i,
		BlockHash:      block.Hash(),
		BlockNumber:    block.NumberU64(),
		BlockIndex:     2,
		ValidatorIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(prepareVote); err != nil {
		cbft.log.Error("Sign PrepareVote failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareVote); err != nil {
		return
	}
	cbft.log.Debug("Send prepare vote", "vote", prepareVote.String())
	cbft.network.Broadcast(prepareVote)
}

func (cbft *Cbft) testVT02Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err prepare vote")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testVT02(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testVT02(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	prepareVote := &protocols.PrepareVote{
		Epoch:          cbft.state.Epoch() + i,
		ViewNumber:     cbft.state.ViewNumber(),
		BlockHash:      block.Hash(),
		BlockNumber:    block.NumberU64(),
		BlockIndex:     2,
		ValidatorIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(prepareVote); err != nil {
		cbft.log.Error("Sign PrepareVote failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(prepareVote); err != nil {
		return
	}
	cbft.log.Debug("Send prepare vote", "vote", prepareVote.String())
	cbft.network.Broadcast(prepareVote)
}

func (cbft *Cbft) testVC01Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err view change")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testVC01(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testVC01(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	view := &protocols.ViewChange{
		Epoch:          cbft.state.Epoch(),
		ViewNumber:     cbft.state.ViewNumber() + i,
		BlockHash:      block.Hash(),
		BlockNumber:    block.NumberU64(),
		ValidatorIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(view); err != nil {
		cbft.log.Error("Sign ViewChange failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(view); err != nil {
		return
	}
	cbft.log.Debug("Send prepare vote", "vote", view.String())
	cbft.network.Broadcast(view)
}

func (cbft *Cbft) testVC02Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err view change")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testVC02(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testVC02(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	block := testNewBlock(cbft.state.HighestQCBlock().Hash(), cbft.state.HighestQCBlock().NumberU64()+i)
	view := &protocols.ViewChange{
		Epoch:          cbft.state.Epoch() + i,
		ViewNumber:     cbft.state.ViewNumber(),
		BlockHash:      block.Hash(),
		BlockNumber:    block.NumberU64(),
		ValidatorIndex: cbft.byzantiumIndex,
	}
	if err := cbft.signMsgByBls(view); err != nil {
		cbft.log.Error("Sign ViewChange failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}
	if err := cbft.byzantium.SetBuildMsg(view); err != nil {
		return
	}
	cbft.log.Debug("Send prepare vote", "vote", view.String())
	cbft.network.Broadcast(view)
}

func (cbft *Cbft) testVQ05Loop() {
	ticker := time.NewTicker(1 * time.Second)
	cbft.log.Debug("byzantine test start test loop of send err view change qc")
	for {
		select {
		case <-ticker.C:
			cbft.testVQ05()
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testVQ05() {
	if !cbft.IsStartEvil() {
		return
	}
	qcs := make([]*ctypes.ViewChangeQuorumCert, 0)
	qcNumber, qcHash := cbft.HighestQCBlockBn()
	qc, err := cbft.testGenerateQC(qcHash, qcNumber)
	if err != nil {
		return
	}
	qcs = append(qcs, qc)
	lockNumber, lockHash := cbft.HighestLockBlockBn()
	qc, err = cbft.testGenerateQC(lockHash, lockNumber)
	if err != nil {
		return
	}
	qcs = append(qcs, qc)
	commitNumber, commitHash := cbft.HighestLockBlockBn()
	qc, err = cbft.testGenerateQC(commitHash, commitNumber)
	if err != nil {
		return
	}
	qcs = append(qcs, qc)
	viewQC := &ctypes.ViewChangeQC{QCs: qcs}
	msg := &protocols.ViewChangeQuorumCert{ViewChangeQC: viewQC}
	if err = cbft.byzantium.SetBuildMsg(msg); err != nil {
		return
	}
	cbft.log.Debug("send err view chang qc", "msg", msg.String())
	cbft.network.Broadcast(msg)
}

func (cbft *Cbft) testPQ05Loop() {
	ticker := time.NewTicker(sendTickTime)
	_, blss := testGenerateKeys(cbft.currentValidatorLen())
	cbft.log.Debug("byzantine test start test loop of send err prepare qc")
	for {
		select {
		case <-ticker.C:
			cbft.testPQ05(blss)
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testPQ05(blss []*bls.SecretKey) {
	if !cbft.IsStartEvil() {
		return
	}
	block := cbft.state.PrepareBlockByIndex(cbft.state.NextViewBlockIndex() - 1)
	if block == nil {
		return
	}
	votes := make(map[uint32]*protocols.PrepareVote, 0)
	for i, key := range blss {
		vote, err := cbft.testSignBlock(block, key, uint32(i))
		if err != nil {
			return
		}
		votes[uint32(i)] = vote
	}
	qc := cbft.generatePrepareQC(votes)
	msg := &protocols.BlockQuorumCert{BlockQC: qc}
	if err := cbft.byzantium.SetBuildMsg(msg); err != nil {
		return
	}
	cbft.log.Debug("send err prepare qc", "msg", msg.String())
	cbft.network.Broadcast(msg)
}

func (cbft *Cbft) testSY01Loop() {
	ticker := time.NewTicker(sendTickTime)
	cbft.log.Debug("byzantine test start test loop of send err LatestStatus")
	i := uint64(2)
	for {
		select {
		case <-ticker.C:
			cbft.testSY01(i)
			i++
			if i > 100 {
				i = 2
			}
		case <-cbft.exitCh:
			panic("over")
		}
	}
}

func (cbft *Cbft) testSY01(i uint64) {
	if !cbft.IsStartEvil() {
		return
	}
	localQCNum, localQCHash := cbft.HighestQCBlockBn()
	localLockNum, localLockHash := cbft.HighestLockBlockBn()
	msg := &protocols.LatestStatus{BlockNumber: localQCNum + i, BlockHash: localQCHash,
		LBlockNumber: localLockNum + i, LBlockHash: localLockHash, LogicType: network.TypeForQCBn}
	// if err := cbft.byzantium.SetBuildMsg(msg); err != nil {
	// 	return
	// }
	cbft.log.Debug("Send latest status", "msg", msg.String())
	cbft.network.Broadcast(msg)
}
