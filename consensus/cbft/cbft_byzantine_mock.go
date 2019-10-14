package cbft

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/utils"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/pingcap/failpoint"
	"math/big"
)

func (cbft *Cbft) byzantineMock() {
	me, err := cbft.validatorPool.GetValidatorByNodeID(cbft.state.Epoch(), cbft.NodeID())
	if err != nil || me == nil {
		cbft.log.Warn("Failed to get validator by nodeId", "nodeId", cbft.NodeID().String(), "err", err)
		return
	}
	proposalIndex := me.Index
	cbft.byzantineHandler(proposalIndex)
}

func (cbft *Cbft) byzantineHandler(proposalIndex uint32) {
	failpoint.Inject("Byzantine-PB01", func() {
		cbft.MockPB01(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB02", func() {
		cbft.MockPB02(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB03", func() {
		cbft.MockPB03(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB04", func() {
		cbft.MockPB04(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB06", func(value failpoint.Value) {
		cbft.MockPB06(proposalIndex, value)
	})
	failpoint.Inject("Byzantine-PB07", func() {
		cbft.MockPB07(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB08", func() {
		cbft.MockPB08(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB09", func() {
		cbft.MockPB09(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB10", func() {
		cbft.MockPB10(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB11", func() {
		cbft.MockPB11(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB12", func() {
		cbft.MockPB12(proposalIndex)
	})
}

func mockBlock(blockNumber uint64, parentHash common.Hash) *types.Block {
	header := &types.Header{
		Number:     big.NewInt(int64(blockNumber)),
		ParentHash: parentHash,
	}
	block := types.NewBlockWithHeader(header)
	return block
}

// 验证人恶意产生远大于当前index 的prepare并广播，试图让其他节点FetchPrepare
// 预期结果：其他节点收到此消息，消息签名校验通过，但校验出块人不是当前提议人，不会触发FetchPrepare调用
func (cbft *Cbft) MockPB01(proposalIndex uint32) {
	if !cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber(), proposalIndex) {
		// mock block base qcBlock
		qcBlock := cbft.state.HighestQCBlock()
		block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())

		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    cbft.config.Sys.Amount - 1,
			ProposalIndex: proposalIndex,
		}
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB01]Broadcast future index prepareBlock by validator", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 提议人恶意产生远大于当前index 的prepare并广播，试图让其他节点FetchPrepare
// 预期结果：其他节点收到此消息，消息签名校验通过，校验出块人是当前提议人，触发FetchPrepare调用
func (cbft *Cbft) MockPB02(proposalIndex uint32) {
	if cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber(), proposalIndex) {
		// mock block base qcBlock
		qcBlock := cbft.state.HighestQCBlock()
		block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())

		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    cbft.config.Sys.Amount - 1,
			ProposalIndex: proposalIndex,
		}
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB02]Broadcast future index prepareBlock by proposer", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 验证人恶意产生大于当前viewNumber 的prepare并广播，试图让其他节点FetchBlock
// 预期结果：其他节点收到此消息，消息签名校验通过，校验出块人不是当前提议人，不会触发FetchBlock调用
func (cbft *Cbft) MockPB03(proposalIndex uint32) {
	if !cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber()+1, proposalIndex) {
		// mock block base qcBlock
		qcBlock := cbft.state.HighestQCBlock()
		block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())

		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber() + 1,
			Block:         block,
			BlockIndex:    cbft.config.Sys.Amount - 1,
			ProposalIndex: proposalIndex,
		}
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB03]Broadcast next view prepareBlock by validator", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 下一轮提议人提前进入下一轮view，恶意产生大于当前viewNumber 的prepare并广播，试图让其他节点FetchBlock
// 预期结果：其他节点收到此消息，消息签名校验通过，校验出块人是当前轮提议人，触发FetchBlock调用
func (cbft *Cbft) MockPB04(proposalIndex uint32) {
	if cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber()+1, proposalIndex) {
		// mock block base qcBlock
		qcBlock := cbft.state.HighestQCBlock()
		block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())

		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber() + 1,
			Block:         block,
			BlockIndex:    cbft.config.Sys.Amount - 1,
			ProposalIndex: proposalIndex,
		}
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB04]Broadcast next view prepareBlock by proposer", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 提议人双出
// 预期结果：其他节点收到此消息，记录节点双出证据
func (cbft *Cbft) MockPB06(proposalIndex uint32, value failpoint.Value) {
	nextIndex := cbft.state.NextViewBlockIndex()
	if value == int(nextIndex) {
		currentIndex := nextIndex - 1
		currentBlock := cbft.state.ViewBlockByIndex(currentIndex)

		block := mockBlock(currentBlock.NumberU64(), currentBlock.ParentHash())
		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    currentIndex,
			ProposalIndex: proposalIndex,
		}
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB06]Broadcast duplicate prepareBlock", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 提议人基于lockBlock发出index=0 的prepare，并携带lockBlock的prepareQC、正常的viewChangeQC
// 预期结果：
// 1 lastViewChangeQC 为空，其他节点收到此消息，校验消息必须携带ViewChangeQC
// 2 lastViewChangeQC 不为空，其他节点收到此消息，校验消息不是基于ViewChangeQC.maxBlock产生
func (cbft *Cbft) MockPB07(proposalIndex uint32) {
	lockBlock := cbft.state.HighestLockBlock()
	_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())

	// mock block base lockBlock
	block := mockBlock(lockBlock.NumberU64()+1, lockBlock.Hash())
	prepareBlock := &protocols.PrepareBlock{
		Epoch:         cbft.state.Epoch(),
		ViewNumber:    cbft.state.ViewNumber(),
		Block:         block,
		BlockIndex:    0,
		ProposalIndex: proposalIndex,
	}
	prepareBlock.PrepareQC = lockQC
	prepareBlock.ViewChangeQC = cbft.state.LastViewChangeQC()
	cbft.signMsgByBls(prepareBlock)
	if prepareBlock.ViewChangeQC != nil {
		cbft.log.Warn("[Mock-PB07]Broadcast mock prepareBlock base lock block,normal viewChangeQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String(), "viewChangeQC", prepareBlock.ViewChangeQC.String())
	} else {
		cbft.log.Warn("[Mock-PB07]Broadcast mock prepareBlock base lock block,empty viewChangeQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String())
	}
	cbft.network.Broadcast(prepareBlock)
}

// 提议人基于lockBlock发出index=0 的prepare，并携带lockBlock的prepareQC、伪造maxBlock=lockBlock的viewChangeQC
// 预期结果：其他节点收到此消息，校验viewChangeQC不通过
func (cbft *Cbft) MockPB08(proposalIndex uint32) {
	mockViewChangeQC := func(viewChangeQC *ctypes.ViewChangeQC, lockQC *ctypes.QuorumCert) *ctypes.ViewChangeQC {
		mock := &ctypes.ViewChangeQC{}
		for _, qc := range viewChangeQC.QCs {
			if qc.BlockNumber <= lockQC.BlockNumber {
				mock.QCs = append(mock.QCs, qc)
			} else if qc.BlockNumber > lockQC.BlockNumber {
				c := qc.Copy()
				c.BlockNumber = lockQC.BlockNumber
				c.BlockHash = lockQC.BlockHash
				c.BlockEpoch = lockQC.Epoch
				c.BlockViewNumber = lockQC.ViewNumber
				mock.QCs = append(mock.QCs, c)
			}
		}
		cbft.log.Warn("[Mock-PB08]mockViewChangeQC", "mockViewChangeQC", mock.String())
		return mock
	}

	if cbft.state.LastViewChangeQC() != nil && len(cbft.state.LastViewChangeQC().QCs) > 0 {
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())

		// mock block base lockBlock
		block := mockBlock(lockBlock.NumberU64()+1, lockBlock.Hash())
		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    0,
			ProposalIndex: proposalIndex,
		}
		prepareBlock.PrepareQC = lockQC
		prepareBlock.ViewChangeQC = mockViewChangeQC(cbft.state.LastViewChangeQC(), lockQC)
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB08]Broadcast mock prepareBlock base lock block,fake viewChangeQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String(), "viewChangeQC", prepareBlock.ViewChangeQC.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 提议人基于lockBlock发出index=0 的prepare，并携带lockBlock的prepareQC，不携带viewChangeQC
// 预期结果：其他节点收到此消息，校验消息必须携带ViewChangeQC
func (cbft *Cbft) MockPB09(proposalIndex uint32) {
	if cbft.state.LastViewChangeQC() != nil && len(cbft.state.LastViewChangeQC().QCs) > 0 {
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())

		// mock block base lockBlock
		block := mockBlock(lockBlock.NumberU64()+1, lockBlock.Hash())
		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    0,
			ProposalIndex: proposalIndex,
		}
		prepareBlock.PrepareQC = lockQC
		prepareBlock.ViewChangeQC = nil
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB09]Broadcast mock prepareBlock base lock block,empty viewChangeQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 提议人基于qcBlock发出index=0 的prepare，并携带lockBlock的prepareQC，正常的viewChangeQC
// 预期结果：其他节点收到此消息，校验prepareQC不通过
func (cbft *Cbft) MockPB10(proposalIndex uint32) {
	if cbft.state.LastViewChangeQC() != nil && len(cbft.state.LastViewChangeQC().QCs) > 0 {
		qcBlock := cbft.state.HighestQCBlock()
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())

		// mock block base qcBlock
		block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())
		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         block,
			BlockIndex:    0,
			ProposalIndex: proposalIndex,
		}
		prepareBlock.PrepareQC = lockQC
		prepareBlock.ViewChangeQC = cbft.state.LastViewChangeQC()
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB10]Broadcast mock prepareBlock base qc block,fake prepareQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String())
		cbft.network.Broadcast(prepareBlock)
	}
}

// 下一轮提议人恶意提前进入下一轮view，基于上一轮最新确认的区块发出index=0 的prepare，并携带正确的prepareQC，伪造多份自己签名的viewChangeQC，试图让其他节点changeView
// 预期结果：其他节点收到此消息，校验viewChangeQC 不通过
func (cbft *Cbft) MockPB11(proposalIndex uint32) {
	mockViewChangeQC := func(qc *ctypes.QuorumCert) *ctypes.ViewChangeQC {
		mock := &ctypes.ViewChangeQC{}
		viewChange := &protocols.ViewChange{
			Epoch:          cbft.state.Epoch(),
			ViewNumber:     cbft.state.ViewNumber(),
			BlockHash:      qc.BlockHash,
			BlockNumber:    qc.BlockNumber,
			ValidatorIndex: proposalIndex,
			PrepareQC:      qc,
		}
		cbft.signMsgByBls(viewChange)
		cert, _ := cbft.generateViewChangeQuorumCert(viewChange)

		mock.QCs = append(mock.QCs, cert)
		cbft.log.Warn("[Mock-PB11]mockViewChangeQC", "mockViewChangeQC", mock.String())
		return mock
	}

	if cbft.state.LastViewChangeQC() != nil && len(cbft.state.LastViewChangeQC().QCs) > 0 {
		if cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber()+1, proposalIndex) {
			qcBlock := cbft.state.HighestQCBlock()
			_, qc := cbft.blockTree.FindBlockAndQC(qcBlock.Hash(), qcBlock.NumberU64())

			// mock block base qcBlock
			block := mockBlock(qcBlock.NumberU64()+1, qcBlock.Hash())
			prepareBlock := &protocols.PrepareBlock{
				Epoch:         cbft.state.Epoch(),
				ViewNumber:    cbft.state.ViewNumber() + 1,
				Block:         block,
				BlockIndex:    0,
				ProposalIndex: proposalIndex,
			}
			prepareBlock.PrepareQC = qc
			prepareBlock.ViewChangeQC = mockViewChangeQC(qc)
			cbft.signMsgByBls(prepareBlock)
			cbft.log.Warn("[Mock-PB11]Broadcast mock prepareBlock base qc block,fake viewChangeQC", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String(), "viewChangeQC", prepareBlock.ViewChangeQC.String())
			cbft.network.Broadcast(prepareBlock)
		}
	}
}

// 下一轮提议人恶意提前进入下一轮view，伪造前一轮view的最后2个区块，并基于伪造的区块发出index=0 的prepare，并携带伪造的prepareQC，试图让其他节点changeView
// 预期结果：其他节点收到此消息，校验viewChangeQC 不通过
func (cbft *Cbft) MockPB12(proposalIndex uint32) {
	if cbft.isProposer(cbft.state.Epoch(), cbft.state.ViewNumber()+1, proposalIndex) {
		qcBlock := cbft.state.HighestQCBlock()
		_, qc := cbft.blockTree.FindBlockAndQC(qcBlock.Hash(), qcBlock.NumberU64())

		// mock block base qcBlock
		block := mockBlock(qcBlock.NumberU64()+2, common.BytesToHash(utils.Rand32Bytes(32)))
		prepareBlock := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber() + 1,
			Block:         block,
			BlockIndex:    0,
			ProposalIndex: proposalIndex,
		}
		prepareBlock.PrepareQC = qc
		cbft.signMsgByBls(prepareBlock)
		cbft.log.Warn("[Mock-PB12]Broadcast next view prepareBlock", "nodeId", cbft.NodeID(), "prepareBlock", prepareBlock.String(), "prepareQC", prepareBlock.PrepareQC.String())
		cbft.network.Broadcast(prepareBlock)
	}
}
