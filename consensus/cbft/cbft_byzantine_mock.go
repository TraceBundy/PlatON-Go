package cbft

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/pingcap/failpoint"
)

// 提议人双出
func (cbft *Cbft) MockPB03(proposalIndex uint32) {
	failpoint.Inject("Mock-PB03", func(value failpoint.Value) {
		nextIndex := cbft.state.NextViewBlockIndex()
		if value == int(nextIndex) {
			preIndex := nextIndex - 1
			preBlock := cbft.state.ViewBlockByIndex(preIndex)

			header := &types.Header{
				Number:     preBlock.Number(),
				ParentHash: preBlock.ParentHash(),
			}
			dupBlock := types.NewBlockWithHeader(header)
			dupPB := &protocols.PrepareBlock{
				Epoch:         cbft.state.Epoch(),
				ViewNumber:    cbft.state.ViewNumber(),
				Block:         dupBlock,
				BlockIndex:    preIndex,
				ProposalIndex: proposalIndex,
			}
			cbft.signMsgByBls(dupPB)
			cbft.log.Warn("[Mock-PB03]Broadcast duplicate prepareBlock", "nodeId", cbft.NodeID(), "mockPB", dupPB.String())
			cbft.network.Broadcast(dupPB)
		}
	})
}

// 提议人基于lockBlock发出index=0的prepare，并携带lockBlock的prepareQC、基于qcBlock的viewChangeQC
func (cbft *Cbft) MockPB04(proposalIndex uint32) {
	failpoint.Inject("Mock-PB04", func() {
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
	})
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

	failpoint.Inject("Mock-PB05", func() {
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
	})
}

// 提议人基于qcBlock发出index=0的prepare，并携带lockBlock的prepareQC，基于qcBlock的viewChangeQC
func (cbft *Cbft) MockPB06(proposalIndex uint32) {
	failpoint.Inject("Mock-PB06", func() {
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
	})
}

// 提议人基于lockBlock发出index=0的prepare，并携带lockBlock的prepareQC，不携带viewChangeQC
func (cbft *Cbft) MockPB07(proposalIndex uint32) {
	failpoint.Inject("Mock-PB07", func() {
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
	})
}
