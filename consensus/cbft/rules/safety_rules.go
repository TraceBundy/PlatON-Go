package rules

import (
	"fmt"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/state"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
)

type SafetyError interface {
	error
	Fetch() bool   //Is the error need fetch
	NewView() bool //need change view
}

type safetyError struct {
	text    string
	fetch   bool
	newView bool
}

func (s safetyError) Error() string {
	return s.text
}

func (s safetyError) Fetch() bool {
	return s.fetch
}
func (s safetyError) NewView() bool {
	return s.newView
}

//func newSafetyError(text string, fetch, newView bool) SafetyError {
//	return &safetyError{
//		text:    text,
//		fetch:   fetch,
//		newView: newView,
//	}
//}

func newFetchError(text string) SafetyError {
	return &safetyError{
		text:    text,
		fetch:   true,
		newView: false,
	}
}
func newViewError(text string) SafetyError {
	return &safetyError{
		text:    text,
		fetch:   false,
		newView: true,
	}
}

func newError(text string) SafetyError {
	return &safetyError{
		text:    text,
		fetch:   false,
		newView: false,
	}
}

type SafetyRules interface {
	// Security rules for proposed blocks
	PrepareBlockRules(block *protocols.PrepareBlock) SafetyError

	// Security rules for proposed votes
	PrepareVoteRules(vote *protocols.PrepareVote) SafetyError

	// Security rules for viewChange
	ViewChangeRules(vote *protocols.ViewChange) SafetyError

	// Security rules for qcblock
	QCBlockRules(block *types.Block, qc *ctypes.QuorumCert) SafetyError
}

type baseSafetyRules struct {
	viewState *state.ViewState
	blockTree *ctypes.BlockTree
	config    *ctypes.Config
}

// PrepareBlock rules
// 1.Less than local viewNumber drop
// 2.Synchronization greater than local viewNumber
// 3.Lost more than the time window
func (r *baseSafetyRules) PrepareBlockRules(block *protocols.PrepareBlock) SafetyError {
	isQCChild := func() bool {
		return block.BlockNum() == r.viewState.HighestQCBlock().NumberU64()+1 &&
			block.Block.ParentHash() == r.viewState.HighestQCBlock().Hash() &&
			r.blockTree.FindBlockByHash(block.Block.ParentHash()) != nil
	}

	isLockChild := func() bool {
		return block.BlockNum() == r.viewState.HighestLockBlock().NumberU64()+1 &&
			block.Block.ParentHash() == r.viewState.HighestLockBlock().Hash() &&
			r.blockTree.FindBlockByHash(block.Block.ParentHash()) != nil
	}

	acceptViewChangeQC := func() bool {
		if block.ViewChangeQC == nil {
			return r.config.Sys.Amount == r.viewState.MaxQCIndex()+1
		}
		_, _, _, _, hash, number := block.ViewChangeQC.MaxBlock()
		return number+1 == block.Block.NumberU64() && block.Block.ParentHash() == hash
	}

	isFirstBlock := func() bool {
		return block.BlockIndex == 0
	}

	acceptIndexBlock := func() SafetyError {
		if block.BlockIndex >= r.config.Sys.Amount {
			return newError(fmt.Sprintf("blockIndex higher than amount(index:%d, amount:%d)", block.BlockIndex, r.config.Sys.Amount))
		}
		current := r.viewState.ViewBlockByIndex(block.BlockIndex)
		if current != nil {
			return newError(fmt.Sprintf("blockIndex already existed(index:%d)", block.BlockIndex))
		}
		if isFirstBlock() {
			if !isQCChild() && !isLockChild() {
				return newError(fmt.Sprintf("the first index block is not contiguous by local highestQC or highestLock"))
			}
			return nil
		}
		pre := r.viewState.ViewBlockByIndex(block.BlockIndex - 1)
		if pre == nil {
			return newError(fmt.Sprintf("previous index block not existed,discard msg(index:%d)", block.BlockIndex-1))
		}
		if pre.NumberU64() != block.BlockNum()-1 || pre.Hash() != block.Block.ParentHash() {
			return newError(fmt.Sprintf("non contiguous index block(preIndex:%d,preNum:%d,preHash:%s,curIndex:%d,curNum:%d,curParentHash:%s)",
				block.BlockIndex-1, pre.NumberU64(), pre.Hash().String(), block.BlockIndex, block.BlockNum(), block.Block.ParentHash()))
		}
		return nil
	}

	changeEpochBlockRules := func(block *protocols.PrepareBlock) SafetyError {
		if r.viewState.Epoch() > block.Epoch {
			return newError(fmt.Sprintf("epoch too low(local:%d, msg:%d)", r.viewState.Epoch(), block.Epoch))
		}

		if isFirstBlock() && acceptViewChangeQC() && isQCChild() {
			return newViewError("new epoch, need change view")
		}

		return newFetchError(fmt.Sprintf("epoch higher then local(local:%d, msg:%d)", r.viewState.Epoch(), block.Epoch))
	}

	if r.viewState.Epoch() != block.Epoch {
		return changeEpochBlockRules(block)
	}
	if r.viewState.ViewNumber() > block.ViewNumber {
		return newError(fmt.Sprintf("viewNumber too low(local:%d, msg:%d)", r.viewState.ViewNumber(), block.ViewNumber))
	}

	if r.viewState.ViewNumber() < block.ViewNumber {
		isNextView := func() bool {
			return r.viewState.ViewNumber()+1 == block.ViewNumber
		}
		if isNextView() && isFirstBlock() && (isQCChild() || isLockChild()) && acceptViewChangeQC() {
			return newViewError("need change view")
		}
		return newFetchError(fmt.Sprintf("viewNumber higher then local(local:%d, msg:%d)", r.viewState.ViewNumber(), block.ViewNumber))
	}

	// if local epoch and viewNumber is the same with msg
	if err := acceptIndexBlock(); err != nil {
		return err
	}

	if r.viewState.IsDeadline() {
		return newError(fmt.Sprintf("view's deadline is expire(over:%s)", time.Since(r.viewState.Deadline())))
	}
	return nil
}

// PrepareVote rules
// 1.Less than local viewNumber drop
// 2.Synchronization greater than local viewNumber
// 3.Lost more than the time window
func (r *baseSafetyRules) PrepareVoteRules(vote *protocols.PrepareVote) SafetyError {
	existPrepare := func() bool {
		prepare := r.viewState.ViewBlockByIndex(vote.BlockIndex)
		if prepare != nil && prepare.NumberU64() == vote.BlockNumber && prepare.Hash() == vote.BlockHash {
			return true
		}
		return false
	}

	acceptIndexVote := func() SafetyError {
		if vote.BlockIndex >= r.config.Sys.Amount {
			return newError(fmt.Sprintf("voteIndex higher than amount(index:%d, amount:%d)", vote.BlockIndex, r.config.Sys.Amount))
		}
		if r.viewState.FindPrepareVote(vote.BlockIndex, vote.ValidatorIndex) != nil {
			return newError(fmt.Sprintf("prepare vote has exist(blockIndex:%d, validatorIndex:%d)", vote.BlockIndex, vote.ValidatorIndex))
		}
		if !existPrepare() {
			return newError(fmt.Sprintf("current index block not existed,discard msg(index:%d)", vote.BlockIndex))
		}
		return nil
	}

	if r.viewState.Epoch() != vote.Epoch {
		return r.changeEpochVoteRules(vote)
	}
	if r.viewState.ViewNumber() > vote.ViewNumber {
		return newError(fmt.Sprintf("viewNumber too low(local:%d, msg:%d)", r.viewState.ViewNumber(), vote.ViewNumber))
	}

	if r.viewState.ViewNumber() < vote.ViewNumber {
		return newFetchError(fmt.Sprintf("viewNumber higher than local(local:%d, msg:%d)", r.viewState.ViewNumber(), vote.ViewNumber))
	}

	// if local epoch and viewNumber is the same with msg
	if err := acceptIndexVote(); err != nil {
		return err
	}

	if r.viewState.IsDeadline() {
		return newError(fmt.Sprintf("view's deadline is expire(over:%d)", time.Since(r.viewState.Deadline())))
	}
	return nil
}

func (r *baseSafetyRules) changeEpochVoteRules(vote *protocols.PrepareVote) SafetyError {
	if r.viewState.Epoch() > vote.Epoch {
		return newError(fmt.Sprintf("epoch too low(local:%d, msg:%d)", r.viewState.Epoch(), vote.Epoch))
	}

	return newFetchError("new epoch, need fetch blocks")
}

// ViewChange rules
// 1.Less than local viewNumber drop
// 2.Synchronization greater than local viewNumber
func (r *baseSafetyRules) ViewChangeRules(viewChange *protocols.ViewChange) SafetyError {
	if r.viewState.Epoch() != viewChange.Epoch {
		return r.changeEpochViewChangeRules(viewChange)
	}
	if r.viewState.ViewNumber() > viewChange.ViewNumber {
		return newError(fmt.Sprintf("viewNumber too low(local:%d, msg:%d)", r.viewState.ViewNumber(), viewChange.ViewNumber))
	}

	if r.viewState.ViewNumber() < viewChange.ViewNumber {
		return newFetchError(fmt.Sprintf("viewNumber higher then local(local:%d, msg:%d)", r.viewState.ViewNumber(), viewChange.ViewNumber))
	}
	return nil
}

func (r *baseSafetyRules) changeEpochViewChangeRules(viewChange *protocols.ViewChange) SafetyError {
	if r.viewState.Epoch() > viewChange.Epoch {
		return newError(fmt.Sprintf("epoch too low(local:%d, msg:%d)", r.viewState.Epoch(), viewChange.Epoch))
	}

	return newFetchError("new epoch, need fetch blocks")
}

func (r *baseSafetyRules) QCBlockRules(block *types.Block, qc *ctypes.QuorumCert) SafetyError {
	//if r.viewState.Epoch() > qc.Epoch || r.viewState.ViewNumber() > qc.ViewNumber {
	//	return newError(fmt.Sprintf("epoch or viewNumber too low(local:%s, msg:{Epoch:%d,ViewNumber:%d})", r.viewState.ViewString(), qc.Epoch, qc.ViewNumber))
	//}

	if b := r.blockTree.FindBlockByHash(block.ParentHash()); b == nil {
		return newError(fmt.Sprintf("not find parent qc block"))
	}
	if (r.viewState.Epoch() == qc.Epoch && r.viewState.ViewNumber() < qc.ViewNumber) || (r.viewState.Epoch()+1 == qc.Epoch) {
		return newViewError("need change view")
	}
	return nil
}

func NewSafetyRules(viewState *state.ViewState, blockTree *ctypes.BlockTree, config *ctypes.Config) SafetyRules {
	return &baseSafetyRules{
		viewState: viewState,
		blockTree: blockTree,
		config:    config,
	}
}
