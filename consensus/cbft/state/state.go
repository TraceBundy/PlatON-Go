package state

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"sync/atomic"
)

type prepareVotes struct {
	votes []*protocols.PrepareVote
}

func (v *prepareVotes) Clear() {

}

type viewBlocks struct {
	blocks map[uint32]*viewBlock
}

func (v *viewBlocks) Clear() {

}

type viewVotes struct {
	votes map[uint32]*prepareVotes
}

func (v *viewVotes) Clear() {

}

type prepareVoteSet struct {
	votes map[uint32]*protocols.PrepareVote
}

type viewChanges struct {
	viewChanges map[common.Address]*protocols.ViewChange
}

func (v *viewChanges) Clear() {

}

type view struct {
	epoch      uint64
	viewNumber uint64

	//viewchange received by the current view
	viewChanges viewChanges

	//This view has been sent to other verifiers for voting
	hadSendPrepareVote prepareVotes

	//Pending votes of current view, parent block need receive N-f prepareVotes
	pendingVote prepareVotes

	//Current view of the proposed block by the proposer
	viewBlocks viewBlocks

	//The current view generated by the vote
	viewVotes viewVotes
}

func (v *view) Reset() {
	v.epoch = 0
	v.viewNumber = 0
	v.viewChanges.Clear()
	v.hadSendPrepareVote.Clear()
	v.pendingVote.Clear()
	v.viewBlocks.Clear()
	v.viewVotes.Clear()
}

//The block of current view, there two types, prepareBlock and block
type viewBlock interface {
	hash() common.Hash
	number() uint64
	blockIndex() uint32
	//If prepareBlock is an implementation of viewBlock, return prepareBlock, otherwise nil
	prepareBlock() *protocols.PrepareBlock
}

type ViewState struct {

	//Include ViewNumber, viewChanges, prepareVote , proposal block of current view
	*view

	//Highest executed block height
	highestExecutedBlock atomic.Value

	highestQCBlock     atomic.Value
	highestLockBlock   atomic.Value
	highestCommitBlock atomic.Value

	//Set the timer of the view time window
	viewTimer viewTimer
}

func (vs *ViewState) ResetView(epoch uint64, viewNumber uint64) {
	vs.view.Reset()
	vs.view.epoch = epoch
	vs.view.viewNumber = viewNumber
}

func (vs *ViewState) SetHighestExecutedBlock(block *types.Block) {
	vs.highestExecutedBlock.Store(block)
}

func (vs *ViewState) HighestExecutedBlock() *types.Block {
	if v := vs.highestQCBlock.Load(); v == nil {
		panic("Get highest executed block failed")
	} else {
		return v.(*types.Block)
	}
}

func (vs *ViewState) SetHighestQCBlock(ext *types.Block) {
	vs.highestQCBlock.Store(ext)
}

func (vs *ViewState) HighestQCBlock() *types.Block {
	if v := vs.highestQCBlock.Load(); v == nil {
		panic("Get highest qc block failed")
	} else {
		return v.(*types.Block)
	}
}

func (vs *ViewState) SetHighestLockBlock(ext *types.Block) {
	vs.highestLockBlock.Store(ext)
}

func (vs *ViewState) HighestLockBlock() *types.Block {
	if v := vs.highestLockBlock.Load(); v == nil {
		panic("Get highest lock block failed")
	} else {
		return v.(*types.Block)
	}
}

func (vs *ViewState) SetHighestCommitBlock(ext *types.Block) {
	vs.highestCommitBlock.Store(ext)
}

func (vs *ViewState) HighestCommitBlock() *types.Block {
	if v := vs.highestCommitBlock.Load(); v == nil {
		panic("Get highest commit block failed")
	} else {
		return v.(*types.Block)
	}
}