package cbft

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/pingcap/failpoint"
	"math/big"
)

func (cbft *Cbft) byzantineNotify() {
	me, _ := cbft.validatorPool.GetValidatorByNodeID(cbft.state.Epoch(), cbft.NodeID())
	proposalIndex := me.Index
	cbft.byzantineHandler(proposalIndex)
}

func (cbft *Cbft) byzantineHandler(proposalIndex uint32) {
	failpoint.Inject("Byzantine-PB03", func(value failpoint.Value) {
		cbft.MockPB03(proposalIndex, value)
	})
	failpoint.Inject("Byzantine-PB04", func() {
		cbft.MockPB04(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB05", func() {
		cbft.MockPB05(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB06", func() {
		cbft.MockPB06(proposalIndex)
	})
	failpoint.Inject("Byzantine-PB07", func() {
		cbft.MockPB07(proposalIndex)
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

// 提议人基于lockBlock发出index=0 的prepare，并携带lockBlock的prepareQC、基于qcBlock的viewChangeQC
// 预期结果：
func (cbft *Cbft) MockPB07(proposalIndex uint32) {
	if cbft.state.LastViewChangeQC() != nil {
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())
		num := lockBlock.Number()
		header := &types.Header{
			Number:     num.Add(num, common.Big1),
			ParentHash: lockBlock.Hash(),
		}
		b := types.NewBlockWithHeader(header)
		pb := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         b,
			BlockIndex:    cbft.state.NextViewBlockIndex(),
			ProposalIndex: proposalIndex,
		}
		pb.PrepareQC = lockQC
		pb.ViewChangeQC = cbft.state.LastViewChangeQC()
		cbft.signMsgByBls(pb)
		cbft.log.Warn("[Mock-PB04]Broadcast mock prepareBlock base lock block,normal viewChangeQC", "nodeId", cbft.NodeID(), "mockPB", pb.String(), "mockPB.prepareQC", pb.PrepareQC.String(), "mockPB.viewChangeQC", pb.ViewChangeQC.String())
		cbft.network.Broadcast(pb)
	}
}

// 提议人基于lockBlock发出index=0的prepare，并携带lockBlock的prepareQC、伪造maxBlock=lockBlock的viewChangeQC
func (cbft *Cbft) MockPB05(proposalIndex uint32) {
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
		cbft.log.Warn("[Mock-PB05]mockViewChangeQC", "mockViewChangeQC", mock.String())
		return mock
	}

	if cbft.state.LastViewChangeQC() != nil {
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())
		num := lockBlock.Number()
		header := &types.Header{
			Number:     num.Add(num, common.Big1),
			ParentHash: lockBlock.Hash(),
		}
		b := types.NewBlockWithHeader(header)
		pb := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         b,
			BlockIndex:    cbft.state.NextViewBlockIndex(),
			ProposalIndex: proposalIndex,
		}
		pb.PrepareQC = lockQC
		pb.ViewChangeQC = mockViewChangeQC(cbft.state.LastViewChangeQC(), lockQC)
		cbft.signMsgByBls(pb)
		cbft.log.Warn("[Mock-PB05]Broadcast mock prepareBlock base lock block,fake viewChangeQC", "nodeId", cbft.NodeID(), "mockPB", pb.String(), "mockPB.prepareQC", pb.PrepareQC.String(), "mockPB.viewChangeQC", pb.ViewChangeQC.String())
		cbft.network.Broadcast(pb)
	}
}

// 提议人基于qcBlock发出index=0的prepare，并携带lockBlock的prepareQC，基于qcBlock的viewChangeQC
func (cbft *Cbft) MockPB06(proposalIndex uint32) {
	if cbft.state.LastViewChangeQC() != nil {
		qcBlock := cbft.state.HighestQCBlock()
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())
		num := qcBlock.Number()
		header := &types.Header{
			Number:     num.Add(num, common.Big1),
			ParentHash: qcBlock.Hash(),
		}
		b := types.NewBlockWithHeader(header)
		pb := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         b,
			BlockIndex:    cbft.state.NextViewBlockIndex(),
			ProposalIndex: proposalIndex,
		}
		pb.PrepareQC = lockQC
		pb.ViewChangeQC = cbft.state.LastViewChangeQC()
		cbft.signMsgByBls(pb)
		cbft.log.Warn("[Mock-PB06]Broadcast mock prepareBlock base qc block,fake prepareQC", "nodeId", cbft.NodeID(), "mockPB", pb.String(), "mockPB.prepareQC", pb.PrepareQC.String(), "mockPB.viewChangeQC", pb.ViewChangeQC.String())
		cbft.network.Broadcast(pb)
	}
}

// 提议人基于lockBlock发出index=0的prepare，并携带lockBlock的prepareQC，不携带viewChangeQC
func (cbft *Cbft) MockPB07(proposalIndex uint32) {
	if cbft.state.LastViewChangeQC() != nil {
		lockBlock := cbft.state.HighestLockBlock()
		_, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())
		num := lockBlock.Number()
		header := &types.Header{
			Number:     num.Add(num, common.Big1),
			ParentHash: lockBlock.Hash(),
		}
		b := types.NewBlockWithHeader(header)
		pb := &protocols.PrepareBlock{
			Epoch:         cbft.state.Epoch(),
			ViewNumber:    cbft.state.ViewNumber(),
			Block:         b,
			BlockIndex:    cbft.state.NextViewBlockIndex(),
			ProposalIndex: proposalIndex,
		}
		pb.PrepareQC = lockQC
		pb.ViewChangeQC = nil
		cbft.signMsgByBls(pb)
		cbft.log.Warn("[Mock-PB07]Broadcast mock prepareBlock base lock block,miss viewChangeQC", "nodeId", cbft.NodeID(), "mockPB", pb.String(), "mockPB.prepareQC", pb.PrepareQC.String())
		cbft.network.Broadcast(pb)
	}
}
