package state

import (
	"sync/atomic"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"

	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
)

type prepareVotes struct {
	votes map[string]*protocols.PrepareVote
}

func newPrepareVotes() *prepareVotes {
	return &prepareVotes{
		votes: make(map[string]*protocols.PrepareVote),
	}
}

func (p *prepareVotes) hadVote(vote *protocols.PrepareVote) bool {
	for _, v := range p.votes {
		if v.MsgHash() == vote.MsgHash() {
			return true
		}
	}
	return false
}

func (v *prepareVotes) clear() {

}

type viewBlocks struct {
	blocks map[uint32]viewBlock
}

func newViewBlocks() *viewBlocks {
	return &viewBlocks{
		blocks: make(map[uint32]viewBlock),
	}
}

func (v *viewBlocks) addBlock(block viewBlock) {
	v.blocks[block.blockIndex()] = block
}

func (v *viewBlocks) clear() {
	v.blocks = make(map[uint32]viewBlock)
}

func (v *viewBlocks) len() int {
	return len(v.blocks)
}

type viewVotes struct {
	votes map[uint32]*prepareVotes
}

func newViewVotes() *viewVotes {
	return &viewVotes{
		votes: make(map[uint32]*prepareVotes),
	}
}

func (v *viewVotes) addVote(id string, vote *protocols.PrepareVote) {
	if ps, ok := v.votes[vote.BlockIndex]; ok {
		ps.votes[id] = vote
	} else {
		ps := newPrepareVotes()
		ps.votes[id] = vote
		v.votes[vote.BlockIndex] = ps
	}
}

func (v *viewVotes) clear() {
	v.votes = make(map[uint32]*prepareVotes)
}

type viewChanges struct {
	viewChanges map[string]*protocols.ViewChange
}

func newViewChanges() *viewChanges {
	return &viewChanges{
		viewChanges: make(map[string]*protocols.ViewChange),
	}
}

func (v *viewChanges) addViewChange(id string, viewChange *protocols.ViewChange) {
	v.viewChanges[id] = viewChange
}
func (v *viewChanges) clear() {
	v.viewChanges = make(map[string]*protocols.ViewChange)
}

type view struct {
	epoch      uint64
	viewNumber uint64

	//viewchange received by the current view
	viewChanges *viewChanges

	//This view has been sent to other verifiers for voting
	hadSendPrepareVote *prepareVotes

	//Pending votes of current view, parent block need receive N-f prepareVotes
	pendingVote *prepareVotes

	//Current view of the proposed block by the proposer
	viewBlocks *viewBlocks

	//The current view generated by the vote
	viewVotes *viewVotes
}

func newView() *view {
	return &view{
		viewChanges:        newViewChanges(),
		hadSendPrepareVote: newPrepareVotes(),
		pendingVote:        newPrepareVotes(),
		viewBlocks:         newViewBlocks(),
		viewVotes:          newViewVotes(),
	}
}
func (v *view) Reset() {
	v.epoch = 0
	v.viewNumber = 0
	v.viewChanges.clear()
	v.hadSendPrepareVote.clear()
	v.pendingVote.clear()
	v.viewBlocks.clear()
	v.viewVotes.clear()
}

func (v *view) ViewNumber() uint64 {
	return v.viewNumber
}

func (v *view) Epoch() uint64 {
	return v.epoch
}

func (v *view) HadSendPrepareVote(vote *protocols.PrepareVote) bool {
	return v.hadSendPrepareVote.hadVote(vote)
}

//The block of current view, there two types, prepareBlock and block
type viewBlock interface {
	hash() common.Hash
	number() uint64
	blockIndex() uint32
	//If prepareBlock is an implementation of viewBlock, return prepareBlock, otherwise nil
	prepareBlock() *protocols.PrepareBlock
}

type prepareViewBlock struct {
	pb *protocols.PrepareBlock
}

func (p prepareViewBlock) hash() common.Hash {
	return p.pb.Block.Hash()
}

func (p prepareViewBlock) number() uint64 {
	return p.pb.Block.NumberU64()
}
func (p prepareViewBlock) blockIndex() uint32 {
	return p.pb.BlockIndex
}

func (p prepareViewBlock) prepareBlock() *protocols.PrepareBlock {
	return p.pb
}

type qcBlock struct {
	block *types.Block
	qc    *ctypes.QuorumCert
}

func (q qcBlock) hash() common.Hash {
	return q.block.Hash()
}

func (q qcBlock) number() uint64 {
	return q.block.NumberU64()
}
func (q qcBlock) blockIndex() uint32 {
	return q.qc.BlockIndex
}

func (q qcBlock) prepareBlock() *protocols.PrepareBlock {
	return nil
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
	viewTimer *viewTimer
}

func NewViewState() *ViewState {
	return &ViewState{
		view:      newView(),
		viewTimer: newViewTimer(),
	}
}

func (vs *ViewState) ResetView(epoch uint64, viewNumber uint64) {
	vs.view.Reset()
	vs.view.epoch = epoch
	vs.view.viewNumber = viewNumber
}

func (vs *ViewState) Epoch() uint64 {
	return vs.view.epoch
}

func (vs *ViewState) ViewNumber() uint64 {
	return vs.view.viewNumber
}

func (vs *ViewState) Deadline() time.Time {
	return vs.viewTimer.deadline
}

func (vs *ViewState) NumViewBlocks() uint32 {
	return uint32(vs.viewBlocks.len())
}

func (vs *ViewState) AddPrepareBlock(pb *protocols.PrepareBlock) {
	vs.view.viewBlocks.addBlock(&prepareViewBlock{pb})
}

func (vs *ViewState) AddQCBlock(block *types.Block, qc *ctypes.QuorumCert) {
	vs.view.viewBlocks.addBlock(&qcBlock{block: block, qc: qc})
}

func (vs *ViewState) AddPrepareVote(id string, vote *protocols.PrepareVote) {
	vs.view.viewVotes.addVote(id, vote)
}

func (vs *ViewState) AddViewChange(id string, vote *protocols.ViewChange) {
	vs.view.viewChanges.addViewChange(id, vote)
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

func (vs *ViewState) IsDeadline() bool {
	return vs.viewTimer.isDeadline()
}
