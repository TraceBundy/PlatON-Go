package cbft

import (
	"bytes"
	"container/list"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set"

	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"

	"github.com/PlatONnetwork/PlatON-Go/crypto/bls"
	"github.com/pkg/errors"

	"reflect"
	"sync"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/evidence"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/executor"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/fetcher"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/network"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/rules"
	cstate "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/state"
	ctypes "github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/utils"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/validator"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/wal"
	"github.com/PlatONnetwork/PlatON-Go/core/cbfttypes"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/event"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/PlatONnetwork/PlatON-Go/node"
	"github.com/PlatONnetwork/PlatON-Go/p2p"
	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"
	"github.com/PlatONnetwork/PlatON-Go/params"
	"github.com/PlatONnetwork/PlatON-Go/rpc"
)

const (
	cbftVersion = 1

	maxStatQueuesSize = 200
)

type HandleError interface {
	error
	AuthFailed() bool
}

type handleError struct {
	err error
}

func (e handleError) Error() string {
	return e.err.Error()
}

func (e handleError) AuthFailed() bool {
	return false
}

type authFailedError struct {
	err error
}

func (e authFailedError) Error() string {
	return e.err.Error()
}

func (e authFailedError) AuthFailed() bool {
	return true
}

// Cbft is the core structure of the consensus engine
// and is responsible for handling consensus logic.
type Cbft struct {
	config           ctypes.Config
	eventMux         *event.TypeMux
	closeOnce        sync.Once
	exitCh           chan struct{}
	txPool           consensus.TxPoolReset
	blockChain       consensus.ChainReader
	blockCacheWriter consensus.BlockCacheWriter
	peerMsgCh        chan *ctypes.MsgInfo
	syncMsgCh        chan *ctypes.MsgInfo
	evPool           evidence.EvidencePool
	log              log.Logger
	network          *network.EngineManager

	start    int32
	syncing  int32
	fetching int32

	// Commit block error
	commitErrCh chan error
	// Async call channel
	asyncCallCh chan func()

	fetcher *fetcher.Fetcher
	// Control the current view state
	state *cstate.ViewState

	// Block asyncExecutor, the block responsible for executing the current view
	asyncExecutor executor.AsyncBlockExecutor

	// Verification security rules for proposed blocks and viewchange
	safetyRules rules.SafetyRules

	// Determine when to allow voting
	voteRules rules.VoteRules

	// Validator pool
	validatorPool *validator.ValidatorPool

	// Store blocks that are not committed
	blockTree *ctypes.BlockTree

	// wal
	nodeServiceContext   *node.ServiceContext
	wal                  wal.Wal
	bridge               Bridge
	loading              int32
	updateChainStateHook cbfttypes.UpdateChainStateFn

	// Record the number of peer requests for obtaining cbft information.
	queues     map[string]int // Per peer message counts to prevent memory exhaustion.
	queuesLock sync.RWMutex

	// Record message repetitions.
	statQueues       map[common.Hash]map[string]int
	statQueuesLock   sync.RWMutex
	messageHashCache mapset.Set

	// Delay time of each node
	netLatencyMap  map[string]*list.List
	netLatencyLock sync.RWMutex

	//test
	insertBlockQCHook  func(block *types.Block, qc *ctypes.QuorumCert)
	executeFinishHook  func(index uint32)
	consensusNodesMock func() ([]discover.NodeID, error)
}

// New returns a new CBFT.
func New(sysConfig *params.CbftConfig, optConfig *ctypes.OptionsConfig, eventMux *event.TypeMux, ctx *node.ServiceContext) *Cbft {
	cbft := &Cbft{
		config:             ctypes.Config{Sys: sysConfig, Option: optConfig},
		eventMux:           eventMux,
		exitCh:             make(chan struct{}),
		peerMsgCh:          make(chan *ctypes.MsgInfo, optConfig.PeerMsgQueueSize),
		syncMsgCh:          make(chan *ctypes.MsgInfo, optConfig.PeerMsgQueueSize),
		log:                log.New(),
		start:              0,
		syncing:            0,
		fetching:           0,
		commitErrCh:        make(chan error, 1),
		asyncCallCh:        make(chan func(), optConfig.PeerMsgQueueSize),
		fetcher:            fetcher.NewFetcher(),
		nodeServiceContext: ctx,
		queues:             make(map[string]int),
		statQueues:         make(map[common.Hash]map[string]int),
		messageHashCache:   mapset.NewSet(),
		netLatencyMap:      make(map[string]*list.List),
	}

	if evPool, err := evidence.NewEvidencePool(ctx, optConfig.EvidenceDir); err == nil {
		cbft.evPool = evPool
	} else {
		return nil
	}

	return cbft
}

func NewFaker() consensus.Engine {
	c := new(consensus.BftMock)
	c.Blocks = make([]*types.Block, 0)
	return c
}

// Start starts consensus engine.
func (cbft *Cbft) Start(chain consensus.ChainReader, blockCacheWriter consensus.BlockCacheWriter, txPool consensus.TxPoolReset, agency consensus.Agency) error {
	cbft.log.Info("~ Start cbft consensus")
	cbft.blockChain = chain
	cbft.txPool = txPool
	cbft.blockCacheWriter = blockCacheWriter
	cbft.asyncExecutor = executor.NewAsyncExecutor(blockCacheWriter.Execute)
	cbft.validatorPool = validator.NewValidatorPool(agency, chain.CurrentHeader().Number.Uint64(), cbft.config.Option.NodeID)

	cbft.state = cstate.NewViewState(cbft.config.Sys.Period)
	//Initialize block tree
	block := chain.GetBlock(chain.CurrentHeader().Hash(), chain.CurrentHeader().Number.Uint64())

	isGenesis := func() bool {
		return block.NumberU64() == 0
	}

	var qc *ctypes.QuorumCert
	if !isGenesis() {
		var err error
		_, qc, err = ctypes.DecodeExtra(block.ExtraData())

		if err != nil {
			cbft.log.Error("It's not genesis", "err", err)
			return errors.Wrap(err, fmt.Sprintf("start cbft failed"))
		}
	}

	cbft.blockTree = ctypes.NewBlockTree(block, qc)
	utils.SetTrue(&cbft.loading)
	if isGenesis() {
		cbft.changeView(cstate.DefaultEpoch, cstate.DefaultViewNumber, block, qc, nil)
	} else {
		cbft.changeView(qc.Epoch, qc.ViewNumber, block, qc, nil)
	}

	//Initialize view state
	cbft.state.SetHighestQCBlock(block)
	cbft.state.SetHighestLockBlock(block)
	cbft.state.SetHighestCommitBlock(block)

	// Initialize current view
	if qc != nil {
		cbft.state.SetExecuting(qc.BlockIndex, true)
		cbft.state.AddQCBlock(block, qc)
		cbft.state.AddQC(qc)
	}

	// try change view again
	cbft.tryChangeView()

	//Initialize rules
	cbft.safetyRules = rules.NewSafetyRules(cbft.state, cbft.blockTree, &cbft.config)
	cbft.voteRules = rules.NewVoteRules(cbft.state)

	// load consensus state
	if err := cbft.LoadWal(); err != nil {
		cbft.log.Error("Load wal failed", "err", err)
		return err
	}
	utils.SetFalse(&cbft.loading)

	// init handler and router to process message.
	// cbft -> handler -> router.
	cbft.network = network.NewEngineManger(cbft) // init engineManager as handler.

	go cbft.receiveLoop()

	// Start the handler to process the message.
	go cbft.network.Start()

	cbft.fetcher.Start()

	utils.SetTrue(&cbft.start)
	cbft.log.Info("Cbft engine start")
	return nil
}

// ReceiveMessage Entrance: The messages related to the consensus are entered from here.
// The message sent from the peer node is sent to the CBFT message queue and
// there is a loop that will distribute the incoming message.
func (cbft *Cbft) ReceiveMessage(msg *ctypes.MsgInfo) error {
	if !cbft.running() {
		cbft.log.Trace("Cbft not running, stop process message", "fecthing", utils.True(&cbft.fetching), "syncing", utils.True(&cbft.syncing))
		return nil
	}

	err := cbft.recordMessage(msg)
	//cbft.log.Debug("Record message", "type", fmt.Sprintf("%T", msg.Msg), "msgHash", msg.Msg.MsgHash(), "duration", time.Since(begin))
	if err != nil {
		cbft.log.Error("ReceiveMessage failed", "err", err)
		return err
	}

	// Repeat filtering on consensus messages.
	// First check.
	if cbft.network.ContainsHistoryMessageHash(msg.Msg.MsgHash()) {
		cbft.log.Trace("Processed message for ReceiveMessage, no need to process", "msgHash", msg.Msg.MsgHash())
		cbft.forgetMessage(msg.PeerID)
		return nil
	}

	select {
	case cbft.peerMsgCh <- msg:
		cbft.log.Debug("Received message from peer", "type", fmt.Sprintf("%T", msg.Msg), "msgHash", msg.Msg.MsgHash(), "BHash", msg.Msg.BHash(), "msg", msg.String(), "peerMsgCh", len(cbft.peerMsgCh))
	case <-cbft.exitCh:
		cbft.log.Error("Cbft exit")
	default:
		cbft.log.Debug("peerMsgCh is full, discard", "peerMsgCh", len(cbft.peerMsgCh))
	}
	return nil
}

// recordMessage records the number of messages sent by each node,
// mainly to prevent Dos attacks
func (cbft *Cbft) recordMessage(msg *ctypes.MsgInfo) error {
	cbft.queuesLock.Lock()
	defer cbft.queuesLock.Unlock()
	count := cbft.queues[msg.PeerID] + 1
	if int64(count) > cbft.config.Option.MaxQueuesLimit {
		log.Error("Discarded message, exceeded allowance for the layer of cbft", "peer", msg.PeerID, "msgHash", msg.Msg.MsgHash().TerminalString())
		// Need further confirmation.
		// todo: Is the program exiting or dropping the message here?
		return fmt.Errorf("execeed max queues limit")
	}
	cbft.queues[msg.PeerID] = count
	return nil
}

// forgetMessage clears the record after the message processing is completed.
func (cbft *Cbft) forgetMessage(peerID string) error {
	cbft.queuesLock.Lock()
	defer cbft.queuesLock.Unlock()
	// After the message is processed, the counter is decremented by one.
	// If it is reduced to 0, the mapping relationship of the corresponding
	// node will be deleted.
	cbft.queues[peerID]--
	if cbft.queues[peerID] == 0 {
		delete(cbft.queues, peerID)
	}
	return nil
}

// statMessage statistics record of duplicate messages.
func (cbft *Cbft) statMessage(msg *ctypes.MsgInfo) error {
	if msg == nil {
		return fmt.Errorf("invalid msg")
	}
	cbft.statQueuesLock.Lock()
	defer cbft.statQueuesLock.Unlock()

	for cbft.messageHashCache.Cardinality() >= maxStatQueuesSize {
		msgHash := cbft.messageHashCache.Pop().(common.Hash)
		// Printout.
		var bf bytes.Buffer
		for k, v := range cbft.statQueues[msgHash] {
			bf.WriteString(fmt.Sprintf("{%s:%d},", k, v))
		}
		output := strings.TrimSuffix(bf.String(), ",")
		cbft.log.Debug("Statistics sync message", "msgHash", msgHash, "stat", output)
		// remove the key from map.
		delete(cbft.statQueues, msgHash)
	}
	// Reset the variable if there is a difference
	// between the map and the set data.
	if len(cbft.statQueues) > maxStatQueuesSize {
		cbft.messageHashCache.Clear()
		cbft.statQueues = make(map[common.Hash]map[string]int)
	}

	hash := msg.Msg.MsgHash()
	if _, ok := cbft.statQueues[hash]; ok {
		if _, exists := cbft.statQueues[hash][msg.PeerID]; exists {
			cbft.statQueues[hash][msg.PeerID]++
		} else {
			cbft.statQueues[hash][msg.PeerID] = 1
		}
	} else {
		cbft.statQueues[hash] = map[string]int{
			msg.PeerID: 1,
		}
		cbft.messageHashCache.Add(hash)
	}
	return nil
}

// ReceiveSyncMsg is used to receive messages that are synchronized from other nodes.
//
// Possible message types are:
//  PrepareBlockVotesMsg/GetLatestStatusMsg/LatestStatusMsg/
func (cbft *Cbft) ReceiveSyncMsg(msg *ctypes.MsgInfo) error {
	err := cbft.recordMessage(msg)
	if err != nil {
		cbft.log.Error("ReceiveMessage failed", "err", err)
		return err
	}

	// message stat.
	cbft.statMessage(msg)

	// Non-core consensus messages are temporarily not filtered repeatedly.
	select {
	case cbft.syncMsgCh <- msg:
		cbft.log.Debug("Receive synchronization related messages from peer", "msgHash", msg.Msg.MsgHash(), "BHash", msg.Msg.BHash(), "msg", msg.Msg.String(), "syncMsgCh", len(cbft.syncMsgCh))
	case <-cbft.exitCh:
		cbft.log.Error("Cbft exit")
	default:
		cbft.log.Debug("syncMsgCh is full, discard", "syncMsgCh", len(cbft.syncMsgCh))
	}
	return nil
}

// LoadWal tries to recover consensus state and view msg from the wal.
func (cbft *Cbft) LoadWal() (err error) {
	// init wal and load wal state
	var context *node.ServiceContext
	if cbft.config.Option.WalMode {
		context = cbft.nodeServiceContext
	}
	if cbft.wal, err = wal.NewWal(context, ""); err != nil {
		return err
	}
	if cbft.bridge, err = NewBridge(context, cbft); err != nil {
		return err
	}

	// load consensus chainState
	if err = cbft.wal.LoadChainState(cbft.recoveryChainState); err != nil {
		cbft.log.Error(err.Error())
		return err
	}
	// load consensus message
	if err = cbft.wal.Load(cbft.recoveryMsg); err != nil {
		cbft.log.Error(err.Error())
		return err
	}
	return nil
}

// receiveLoop receives all consensus related messages, all processing logic in the same goroutine
func (cbft *Cbft) receiveLoop() {

	// Responsible for handling consensus message logic.
	consensusMessageHandler := func(msg *ctypes.MsgInfo) {
		if !cbft.network.ContainsHistoryMessageHash(msg.Msg.MsgHash()) {
			err := cbft.handleConsensusMsg(msg)
			if err == nil {
				cbft.network.MarkHistoryMessageHash(msg.Msg.MsgHash())
				if err := cbft.network.Forwarding(msg.PeerID, msg.Msg); err != nil {
					cbft.log.Debug("Forward message failed", "err", err)
				}
			} else if err.AuthFailed() {
				// If the verification signature is abnormal,
				// the peer node is added to the local blacklist
				// and disconnected.
				cbft.log.Error("Verify signature failed, will add to blacklist", "peerID", msg.PeerID)
				cbft.network.MarkBlacklist(msg.PeerID)
				cbft.network.RemovePeer(msg.PeerID)
			}
		} else {
			cbft.log.Trace("The message has been processed, discard it", "msgHash", msg.Msg.MsgHash(), "peerID", msg.PeerID)
		}
		cbft.forgetMessage(msg.PeerID)
	}

	// channel Divided into read-only type, writable type
	// Read-only is the channel that gets the current CBFT status.
	// Writable type is the channel that affects the consensus state.
	for {
		select {
		case msg := <-cbft.peerMsgCh:
			consensusMessageHandler(msg)
		default:
		}
		select {
		case msg := <-cbft.peerMsgCh:
			// Forward the message before processing the message.
			consensusMessageHandler(msg)
		case msg := <-cbft.syncMsgCh:
			if err := cbft.handleSyncMsg(msg); err != nil {
				if err, ok := err.(HandleError); ok {
					if err.AuthFailed() {
						cbft.network.MarkBlacklist(msg.PeerID)
						cbft.network.RemovePeer(msg.PeerID)
					}
				}
			}
			cbft.forgetMessage(msg.PeerID)
		case msg := <-cbft.asyncExecutor.ExecuteStatus():
			cbft.onAsyncExecuteStatus(msg)

		case fn := <-cbft.asyncCallCh:
			fn()

		case <-cbft.state.ViewTimeout():
			cbft.OnViewTimeout()
		case err := <-cbft.commitErrCh:
			cbft.OnCommitError(err)
		}
	}
}

// Handling consensus messages, there are three main types of messages. prepareBlock, prepareVote, viewChange
func (cbft *Cbft) handleConsensusMsg(info *ctypes.MsgInfo) HandleError {
	if !cbft.running() {
		cbft.log.Debug("Consensus message pause", "syncing", atomic.LoadInt32(&cbft.syncing), "fetching", atomic.LoadInt32(&cbft.fetching))
		return &handleError{fmt.Errorf("consensus message pause, ignore message")}
	}
	msg, id := info.Msg, info.PeerID
	var err HandleError

	switch msg := msg.(type) {
	case *protocols.PrepareBlock:
		err = cbft.OnPrepareBlock(id, msg)
	case *protocols.PrepareVote:
		err = cbft.OnPrepareVote(id, msg)
	case *protocols.ViewChange:
		err = cbft.OnViewChange(id, msg)
	}

	if err != nil {
		cbft.log.Error("Handle msg Failed", "error", err, "type", reflect.TypeOf(msg), "peer", id, "err", err)
	}
	return err
}

// Behind the node will be synchronized by synchronization message
func (cbft *Cbft) handleSyncMsg(info *ctypes.MsgInfo) error {
	if utils.True(&cbft.syncing) {
		cbft.log.Debug("Currently syncing, consensus message pause")
		return nil
	}
	msg, id := info.Msg, info.PeerID
	var err error
	if !cbft.fetcher.MatchTask(id, msg) {
		switch msg := msg.(type) {
		case *protocols.GetPrepareBlock:
			err = cbft.OnGetPrepareBlock(id, msg)

		case *protocols.GetBlockQuorumCert:
			err = cbft.OnGetBlockQuorumCert(id, msg)

		case *protocols.BlockQuorumCert:
			err = cbft.OnBlockQuorumCert(id, msg)

		case *protocols.GetPrepareVote:
			err = cbft.OnGetPrepareVote(id, msg)

		case *protocols.PrepareVotes:
			err = cbft.OnPrepareVotes(id, msg)

		case *protocols.GetQCBlockList:
			err = cbft.OnGetQCBlockList(id, msg)

		case *protocols.GetLatestStatus:
			err = cbft.OnGetLatestStatus(id, msg)

		case *protocols.LatestStatus:
			err = cbft.OnLatestStatus(id, msg)

		case *protocols.PrepareBlockHash:
			err = cbft.OnPrepareBlockHash(id, msg)

		case *protocols.GetViewChange:
			err = cbft.OnGetViewChange(id, msg)

		case *protocols.ViewChangeQuorumCert:
			err = cbft.OnViewChangeQuorumCert(id, msg)
		case *protocols.ViewChanges:
			err = cbft.OnViewChanges(id, msg)

		}
	}
	return err
}

// running returns whether the consensus engine is running.
func (cbft *Cbft) running() bool {
	return utils.False(&cbft.syncing) && utils.False(&cbft.fetching)
}

// Author returns the current node's Author.
func (cbft *Cbft) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader verify the validity of the block header.
func (cbft *Cbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	if header.Number == nil {
		cbft.log.Error("Verify header fail, unknown block")
		return errors.New("unknown block")
	}

	cbft.log.Trace("Verify header", "number", header.Number, "hash", header.Hash, "seal", seal)
	if len(header.Extra) < consensus.ExtraSeal {
		cbft.log.Error("Verify header fail, missing signature", "number", header.Number, "hash", header.Hash)
	}

	if err := cbft.validatorPool.VerifyHeader(header); err != nil {
		cbft.log.Error("Verify header fail", "number", header.Number, "hash", header.Hash(), "err", err)
	}
	return nil
}

// VerifyHeaders is used to verify the validity of block headers in batch.
func (cbft *Cbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	cbft.log.Trace("Verify headers", "total", len(headers))

	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for _, header := range headers {
			err := cbft.VerifyHeader(chain, header, false)

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (cbft *Cbft) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	cbft.log.Trace("Verify seal", "hash", header.Hash(), "number", header.Number)
	if header.Number.Uint64() == 0 {
		return errors.New("unknown block")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header of running the transactions on top.
func (cbft *Cbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
	cbft.log.Debug("Prepare", "hash", header.Hash(), "number", header.Number.Uint64())

	//header.Extra[0:31] to store block's version info etc. and right pad with 0x00;
	//header.Extra[32:] to store block's sign of producer, the length of sign is 65.
	if len(header.Extra) < 32 {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, 32-len(header.Extra))...)
	}
	header.Extra = header.Extra[:32]

	//init header.Extra[32: 32+65]
	header.Extra = append(header.Extra, make([]byte, consensus.ExtraSeal)...)
	return nil
}

// Finalize implements consensus.Engine, no block
// rewards given, and returns the final block.
func (cbft *Cbft) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	cbft.log.Debug("Finalize block", "hash", header.Hash(), "number", header.Number, "txs", len(txs), "receipts", len(receipts))
	header.Root = state.IntermediateRoot(true)
	return types.NewBlock(header, txs, receipts), nil
}

// Seal is used to generate a block, and block data is
// passed to the execution channel.
func (cbft *Cbft) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	cbft.log.Info("Seal block", "number", block.Number(), "parentHash", block.ParentHash())
	header := block.Header()
	if block.NumberU64() == 0 {
		return errors.New("unknown block")
	}

	sign, err := cbft.signFn(header.SealHash().Bytes())
	if err != nil {
		cbft.log.Error("Seal block sign fail", "number", block.Number(), "parentHash", block.ParentHash(), "err", err)
		return err
	}

	copy(header.Extra[len(header.Extra)-consensus.ExtraSeal:], sign[:])

	sealBlock := block.WithSeal(header)

	cbft.asyncCallCh <- func() {
		cbft.OnSeal(sealBlock, results, stop)
	}
	return nil
}

// OnSeal is used to process the blocks that have already been generated.
func (cbft *Cbft) OnSeal(block *types.Block, results chan<- *types.Block, stop <-chan struct{}) {
	if cbft.state.HighestExecutedBlock().Hash() != block.ParentHash() {
		cbft.log.Warn("Futile block cause highest executed block changed", "number", block.Number(), "parentHash", block.ParentHash(),
			"qcNumber", cbft.state.HighestQCBlock().Number(), "qcHash", cbft.state.HighestQCBlock().Hash(),
			"executedNumber", cbft.state.HighestExecutedBlock().Number(), "executedHash", cbft.state.HighestExecutedBlock().Hash())
		return
	}

	nextRoundNum := validator.NextRound(cbft.state.HighestExecutedBlock().NumberU64())
	me, err := cbft.validatorPool.GetValidatorByNodeID(nextRoundNum, cbft.NodeID())
	if err != nil {
		cbft.log.Warn("Can not got the validator, seal fail", "number", nextRoundNum, "nodeID", cbft.NodeID())
		return
	}
	numValidators := cbft.validatorPool.Len(nextRoundNum)
	currentProposer := cbft.state.ViewNumber() % uint64(numValidators)
	if currentProposer != uint64(me.Index) {
		cbft.log.Warn("You are not the current proposer", "index", me.Index, "currentProposer", currentProposer)
		return
	}

	prepareBlock := &protocols.PrepareBlock{
		Epoch:         cbft.state.Epoch(),
		ViewNumber:    cbft.state.ViewNumber(),
		Block:         block,
		BlockIndex:    cbft.state.NextViewBlockIndex(),
		ProposalIndex: uint32(me.Index),
	}

	// Next index is equal zero, This view does not produce a block.
	if cbft.state.NextViewBlockIndex() == 0 {
		parentBlock, parentQC := cbft.blockTree.FindBlockAndQC(block.ParentHash(), block.NumberU64()-1)
		if parentBlock == nil {
			cbft.log.Error("Can not find parent block", "number", block.Number(), "parentHash", block.ParentHash())
			return
		}
		prepareBlock.PrepareQC = parentQC
		prepareBlock.ViewChangeQC = cbft.state.LastViewChangeQC()
	}

	cbft.log.Info("Seal New Block", "prepareBlock", prepareBlock.String())

	if err := cbft.signMsgByBls(prepareBlock); err != nil {
		cbft.log.Error("Sign PrepareBlock failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}

	cbft.state.SetExecuting(prepareBlock.BlockIndex, true)

	if err := cbft.OnPrepareBlock("", prepareBlock); err != nil {
		cbft.log.Error("Check Seal Block failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		cbft.state.SetExecuting(prepareBlock.BlockIndex-1, true)
		return
	}

	if err := cbft.signBlock(block.Hash(), block.NumberU64(), prepareBlock.BlockIndex); err != nil {
		cbft.log.Error("Sign PrepareBlock failed", "err", err, "hash", block.Hash(), "number", block.NumberU64())
		return
	}

	cbft.txPool.Reset(block)

	// write sendPrepareBlock info to wal
	if !cbft.isLoading() {
		cbft.bridge.SendPrepareBlock(prepareBlock)
	}

	cbft.findQCBlock()

	cbft.validatorPool.Flush(prepareBlock.Block.Header())

	cbft.network.Broadcast(prepareBlock)
	// Record the number of blocks.
	minedCounter.Inc(1)
	preBlock := cbft.blockTree.FindBlockByHash(block.ParentHash())
	if preBlock != nil {
		blockMinedTimer.UpdateSince(time.Unix(preBlock.Time().Int64(), 0))
	}
	go func() {
		select {
		case <-stop:
			return
		case results <- block:
			blockProduceMeter.Mark(1)
		default:
			cbft.log.Warn("Sealing result channel is not ready by miner", "sealHash", block.Header().SealHash())
		}
	}()
}

// SealHash returns the hash of a block prior to it being sealed.
func (cbft *Cbft) SealHash(header *types.Header) common.Hash {
	cbft.log.Debug("Seal hash", "hash", header.Hash(), "number", header.Number)
	return header.SealHash()
}

// APIs returns a list of APIs provided by the consensus engine.
func (cbft *Cbft) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{
		{
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicConsensusAPI(cbft),
			Public:    true,
		},
		{
			Namespace: "platon",
			Version:   "1.0",
			Service:   NewPublicConsensusAPI(cbft),
			Public:    true,
		},
	}
}

// Protocols return consensus engine to provide protocol information.
func (cbft *Cbft) Protocols() []p2p.Protocol {
	return cbft.network.Protocols()
}

// NextBaseBlock is used to calculate the next block.
func (cbft *Cbft) NextBaseBlock() *types.Block {
	result := make(chan *types.Block, 1)
	cbft.asyncCallCh <- func() {
		block := cbft.state.HighestExecutedBlock()
		cbft.log.Debug("Base block", "hash", block.Hash(), "number", block.Number())
		result <- block
	}
	return <-result
}

// InsertChain is used to insert the block into the chain.
func (cbft *Cbft) InsertChain(block *types.Block) error {
	cbft.log.Debug("Insert chain", "number", block.Number(), "hash", block.Hash())

	if block.NumberU64() <= cbft.state.HighestLockBlock().NumberU64() {
		cbft.log.Debug("The inserted block has exists in chain",
			"number", block.Number(), "hash", block.Hash(),
			"lockedNumber", cbft.state.HighestLockBlock().Number(),
			"lockedHash", cbft.state.HighestLockBlock().Hash())
		return nil
	}

	// Verifies block
	_, qc, err := ctypes.DecodeExtra(block.ExtraData())
	if err != nil {
		cbft.log.Error("Decode block extra date fail", "number", block.Number(), "hash", block.Hash())
		return errors.New("failed to decode block extra data")
	}

	if err := cbft.verifyPrepareQC(block.NumberU64(), qc); err != nil {
		cbft.log.Error("Verify prepare QC fail", "number", block.Number(), "hash", block.Hash(), "err", err)
		return err
	}

	parent := cbft.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		cbft.log.Warn("Not found the inserted block's parent block",
			"number", block.Number(), "hash", block.Hash(),
			"parentHash", block.ParentHash(),
			"lockedNumber", cbft.state.HighestLockBlock().Number(),
			"lockedHash", cbft.state.HighestLockBlock().Hash(),
			"qcNumber", cbft.state.HighestQCBlock().Number(),
			"qcHash", cbft.state.HighestQCBlock().Hash())
		return errors.New("orphan block")
	}

	err = cbft.blockCacheWriter.Execute(block, parent)
	if err != nil {
		cbft.log.Error("Execting block fail", "number", block.Number(), "hash", block.Hash(), "parent", parent.Hash(), "parentHash", block.ParentHash())
		return errors.New("failed to executed block")
	}
	// FIXME: needed update highest exection block?
	result := make(chan error, 1)
	cbft.asyncCallCh <- func() {
		result <- cbft.OnInsertQCBlock([]*types.Block{block}, []*ctypes.QuorumCert{qc})
	}
	return <-result
}

// HasBlock check if the specified block exists in block tree.
func (cbft *Cbft) HasBlock(hash common.Hash, number uint64) bool {
	// Can only be invoked after startup
	qcBlock := cbft.state.HighestQCBlock()
	return qcBlock.NumberU64() > number || (qcBlock.NumberU64() == number && qcBlock.Hash() == hash)
}

// Status returns the status data of the consensus engine.
func (cbft *Cbft) Status() string {
	type Status struct {
		Tree  *ctypes.BlockTree `json:"block_tree"`
		State *cstate.ViewState `json:"state"`
	}
	status := make(chan string, 1)
	cbft.asyncCallCh <- func() {
		s := &Status{
			Tree:  cbft.blockTree,
			State: cbft.state,
		}
		if t, err := json.Marshal(s); err == nil {
			status <- string(t)
		} else {
			status <- ""
		}
	}
	return <-status
}

// GetPrepareQC returns the QC data of the specified block height.
func (cbft *Cbft) GetPrepareQC(number uint64) *ctypes.QuorumCert {
	cbft.log.Debug("get prepare QC")
	if header := cbft.blockChain.GetHeaderByNumber(number); header != nil {
		if block := cbft.blockChain.GetBlock(header.Hash(), number); block != nil {
			if _, qc, err := ctypes.DecodeExtra(block.ExtraData()); err == nil {
				return qc
			}
		}
	}
	return &ctypes.QuorumCert{}
}

// GetBlockByHash get the specified block by hash.
func (cbft *Cbft) GetBlockByHash(hash common.Hash) *types.Block {
	result := make(chan *types.Block, 1)
	cbft.asyncCallCh <- func() {
		block := cbft.blockTree.FindBlockByHash(hash)
		if block == nil {
			header := cbft.blockChain.GetHeaderByHash(hash)
			if header != nil {
				block = cbft.blockChain.GetBlock(header.Hash(), header.Number.Uint64())
			}
		}
		result <- block
	}
	return <-result
}

// CurrentBlock get the current lock block.
func (cbft *Cbft) CurrentBlock() *types.Block {
	var block *types.Block
	cbft.checkStart(func() {
		block = cbft.state.HighestLockBlock()
	})
	return block
}

func (cbft *Cbft) checkStart(exe func()) {
	cbft.log.Debug("Cbft status", "start", cbft.start)
	if utils.True(&cbft.start) {
		exe()
	}
}

// FastSyncCommitHead processes logic that performs fast synchronization.
func (cbft *Cbft) FastSyncCommitHead(block *types.Block) error {
	cbft.log.Debug("Fast sync commit head", "number", block.Number(), "hash", block.Hash())

	result := make(chan error, 1)
	cbft.asyncCallCh <- func() {
		_, qc, err := ctypes.DecodeExtra(block.ExtraData())
		if err != nil {
			cbft.log.Warn("Decode block extra data fail", "number", block.Number(), "hash", block.Hash())
			result <- errors.New("failed to decode block extra data")
			return
		}

		cbft.blockTree.Reset(block, qc)
		cbft.changeView(qc.Epoch, qc.ViewNumber, block, qc, nil)

		cbft.state.SetHighestQCBlock(block)
		cbft.state.SetHighestLockBlock(block)
		cbft.state.SetHighestCommitBlock(block)

		cbft.validatorPool.Update(block.NumberU64(), cbft.eventMux)

		result <- nil
	}
	return <-result
}

// Close turns off the consensus engine.
func (cbft *Cbft) Close() error {
	cbft.log.Info("Close cbft consensus")
	utils.SetFalse(&cbft.start)
	cbft.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		if cbft.exitCh == nil {
			return
		}
		close(cbft.exitCh)
	})
	if cbft.asyncExecutor != nil {
		cbft.asyncExecutor.Stop()
	}
	return nil
}

// ConsensusNodes returns to the list of consensus nodes.
func (cbft *Cbft) ConsensusNodes() ([]discover.NodeID, error) {
	if cbft.consensusNodesMock != nil {
		return cbft.consensusNodesMock()
	}
	return cbft.validatorPool.ValidatorList(cbft.state.HighestQCBlock().NumberU64()), nil
}

// ShouldSeal check if we can seal block.
func (cbft *Cbft) ShouldSeal(curTime time.Time) (bool, error) {
	if cbft.isLoading() || !cbft.isStart() || !cbft.running() {
		cbft.log.Trace("Should seal fail, cbft not running", "curTime", common.Beautiful(curTime))
		return false, nil
	}

	result := make(chan error, 2)
	cbft.asyncCallCh <- func() {
		cbft.OnShouldSeal(result)
	}
	select {
	case err := <-result:
		if err == nil {
			masterCounter.Inc(1)
		}
		cbft.log.Trace("Should seal", "curTime", common.Beautiful(curTime), "err", err)
		return err == nil, err
	case <-time.After(50 * time.Millisecond):
		result <- errors.New("timeout")
		cbft.log.Trace("Should seal timeout", "curTime", common.Beautiful(curTime), "asyncCallCh", len(cbft.asyncCallCh))
		return false, errors.New("CBFT engine busy")
	}
}

// OnShouldSeal determines whether the current condition
// of the block is satisfied.
func (cbft *Cbft) OnShouldSeal(result chan error) {
	select {
	case <-result:
		cbft.log.Trace("Should seal timeout")
		return
	default:
	}

	if !cbft.running() {
		result <- errors.New("cbft is not running")
		return
	}

	if cbft.state.IsDeadline() {
		result <- fmt.Errorf("view timeout: %s", common.Beautiful(cbft.state.Deadline()))
		return
	}

	currentExecutedBlockNumber := cbft.state.HighestExecutedBlock().NumberU64()
	nextRoundNum := validator.NextRound(currentExecutedBlockNumber)
	if !cbft.validatorPool.IsValidator(nextRoundNum, cbft.config.Option.NodeID) {
		result <- errors.New("current node not a validator")
		return
	}

	numValidators := cbft.validatorPool.Len(nextRoundNum)
	currentProposer := cbft.state.ViewNumber() % uint64(numValidators)
	validator, err := cbft.validatorPool.GetValidatorByNodeID(nextRoundNum, cbft.config.Option.NodeID)
	if err != nil {
		cbft.log.Error("Should seal fail", "err", err)
		result <- err
		return
	}

	if currentProposer != uint64(validator.Index) {
		result <- errors.New("current node not the proposer")
		return
	}

	if cbft.state.NumViewBlocks() >= cbft.config.Sys.Amount {
		result <- errors.New("produce block over limit")
		return
	}

	qcBlock := cbft.state.HighestQCBlock()
	_, qc := cbft.blockTree.FindBlockAndQC(qcBlock.Hash(), qcBlock.NumberU64())
	if cbft.validatorPool.ShouldSwitch(currentExecutedBlockNumber) && qc != nil && qc.Epoch == cbft.state.Epoch() {
		cbft.log.Debug("New epoch, waiting for view's timeout", "executed", currentExecutedBlockNumber, "index", validator.Index)
		result <- errors.New("current node not the proposer")
		return
	}

	rtt := cbft.avgRTT()
	if cbft.state.Deadline().Sub(time.Now()) <= rtt {
		cbft.log.Debug("Not enough time to propagated block, stopped sealing", "deadline", cbft.state.Deadline(), "interval", cbft.state.Deadline().Sub(time.Now()), "rtt", rtt)
		result <- errors.New("not enough time to propagated block, stopped sealing")
		return
	}

	proposerIndexGauage.Update(int64(currentProposer))
	validatorCountGauage.Update(int64(numValidators))
	result <- nil
}

// CalcBlockDeadline return the deadline of the block.
func (cbft *Cbft) CalcBlockDeadline(timePoint time.Time) time.Time {
	produceInterval := time.Duration(cbft.config.Sys.Period/uint64(cbft.config.Sys.Amount)) * time.Millisecond
	rtt := cbft.avgRTT()
	executeTime := (produceInterval - rtt) / 2
	cbft.log.Debug("Calc block deadline", "timePoint", timePoint, "stateDeadline", cbft.state.Deadline(), "produceInterval", produceInterval, "rtt", rtt, "executeTime", executeTime)
	if cbft.state.Deadline().Sub(timePoint) > produceInterval {
		return timePoint.Add(produceInterval - rtt - executeTime)
	}
	return cbft.state.Deadline()
}

// CalcNextBlockTime returns the deadline  of the next block.
func (cbft *Cbft) CalcNextBlockTime(blockTime time.Time) time.Time {
	produceInterval := time.Duration(cbft.config.Sys.Period/uint64(cbft.config.Sys.Amount)) * time.Millisecond
	rtt := cbft.avgRTT()
	executeTime := (produceInterval - rtt) / 2
	cbft.log.Debug("Calc next block time",
		"blockTime", blockTime, "now", time.Now(), "produceInterval", produceInterval,
		"period", cbft.config.Sys.Period, "amount", cbft.config.Sys.Amount,
		"interval", time.Since(blockTime), "rtt", rtt, "executeTime", executeTime)
	if time.Since(blockTime) < produceInterval {
		return blockTime.Add(executeTime + rtt)
	}
	// Commit new block immediately.
	return blockTime.Add(produceInterval)
}

// IsConsensusNode returns whether the current node is a consensus node.
func (cbft *Cbft) IsConsensusNode() bool {
	return cbft.validatorPool.IsValidator(cbft.state.HighestQCBlock().NumberU64(), cbft.config.Option.NodeID)
}

// GetBlock returns the block corresponding to the specified number and hash.
func (cbft *Cbft) GetBlock(hash common.Hash, number uint64) *types.Block {
	result := make(chan *types.Block, 1)
	cbft.asyncCallCh <- func() {
		block, _ := cbft.blockTree.FindBlockAndQC(hash, number)
		result <- block
	}
	return <-result
}

// GetBlockWithoutLock returns the block corresponding to the specified number and hash.
func (cbft *Cbft) GetBlockWithoutLock(hash common.Hash, number uint64) *types.Block {
	block, _ := cbft.blockTree.FindBlockAndQC(hash, number)
	return block
}

// IsSignedBySelf returns the verification result , and the result is
// to determine whether the block information is the signature of the current node.
func (cbft *Cbft) IsSignedBySelf(sealHash common.Hash, header *types.Header) bool {
	return cbft.verifySelfSigned(sealHash.Bytes(), header.Signature())
}

// TracingSwitch will be abandoned in the future.
func (Cbft) TracingSwitch(flag int8) {
	panic("implement me")
}

// Config returns the configuration information of the consensus engine.
func (cbft *Cbft) Config() *ctypes.Config {
	return &cbft.config
}

// HighestCommitBlockBn returns the highest submitted block number of the current node.
func (cbft *Cbft) HighestCommitBlockBn() (uint64, common.Hash) {
	return cbft.state.HighestCommitBlock().NumberU64(), cbft.state.HighestCommitBlock().Hash()
}

// HighestLockBlockBn returns the highest locked block number of the current node.
func (cbft *Cbft) HighestLockBlockBn() (uint64, common.Hash) {
	return cbft.state.HighestLockBlock().NumberU64(), cbft.state.HighestLockBlock().Hash()
}

// HighestQCBlockBn return the highest QC block number of the current node.
func (cbft *Cbft) HighestQCBlockBn() (uint64, common.Hash) {
	return cbft.state.HighestQCBlock().NumberU64(), cbft.state.HighestQCBlock().Hash()
}

func (cbft *Cbft) threshold(num int) int {
	return num - (num-1)/3
}

func (cbft *Cbft) commitBlock(commitBlock *types.Block, commitQC *ctypes.QuorumCert, lockBlock *types.Block, qcBlock *types.Block) {
	extra, err := ctypes.EncodeExtra(byte(cbftVersion), commitQC)
	if err != nil {
		cbft.log.Error("Encode extra error", "nubmer", commitBlock.Number(), "hash", commitBlock.Hash(), "cbftVersion", cbftVersion)
		return
	}

	cbft.log.Debug("Send consensus result to worker", "number", commitBlock.Number(), "hash", commitBlock.Hash())

	lockBlock, lockQC := cbft.blockTree.FindBlockAndQC(lockBlock.Hash(), lockBlock.NumberU64())
	qcBlock, qcQC := cbft.blockTree.FindBlockAndQC(qcBlock.Hash(), qcBlock.NumberU64())
	if cbft.updateChainStateHook != nil {
		cbft.updateChainStateHook(&protocols.State{qcBlock, qcQC}, &protocols.State{lockBlock, lockQC}, &protocols.State{commitBlock, commitQC})
	}
	qcState := &protocols.State{qcBlock, qcQC}
	lockState := &protocols.State{lockBlock, lockQC}
	commitState := &protocols.State{commitBlock, commitQC}
	cbft.eventMux.Post(cbfttypes.CbftResult{
		Block:              commitBlock,
		ExtraData:          extra,
		SyncState:          cbft.commitErrCh,
		ChainStateUpdateCB: func() { cbft.bridge.UpdateChainState(qcState, lockState, commitState) },
	})
}

// Evidences implements functions in API.
func (cbft *Cbft) Evidences() string {
	evs := cbft.evPool.Evidences()
	if len(evs) == 0 {
		return "{}"
	}
	evds := evidence.ClassifyEvidence(evs)
	js, err := json.MarshalIndent(evds, "", "  ")
	if err != nil {
		return ""
	}
	return string(js)
}

func (cbft *Cbft) verifySelfSigned(m []byte, sig []byte) bool {
	recPubKey, err := crypto.Ecrecover(m, sig)
	if err != nil {
		return false
	}

	pubKey := cbft.config.Option.NodePriKey.PublicKey
	pbytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	if !bytes.Equal(pbytes, recPubKey) {
		return false
	}
	return true
}

// signFn use private key to sign byte slice.
func (cbft *Cbft) signFn(m []byte) ([]byte, error) {
	return crypto.Sign(m, cbft.config.Option.NodePriKey)
}

// signFn use bls private key to sign byte slice.
func (cbft *Cbft) signFnByBls(m []byte) ([]byte, error) {
	sign := cbft.config.Option.BlsPriKey.Sign(string(m))
	return sign.Serialize(), nil
}

// signMsg use bls private key to sign msg.
func (cbft *Cbft) signMsgByBls(msg ctypes.ConsensusMsg) error {
	buf, err := msg.CannibalizeBytes()
	if err != nil {
		return err
	}
	sign, err := cbft.signFnByBls(buf)
	if err != nil {
		return err
	}
	msg.SetSign(sign)
	return nil
}

func (cbft *Cbft) isLoading() bool {
	return utils.True(&cbft.loading)
}

func (cbft *Cbft) isStart() bool {
	return utils.True(&cbft.start)
}

func (cbft *Cbft) currentProposer() *cbfttypes.ValidateNode {
	block := cbft.state.HighestQCBlock()
	_, qc := cbft.blockTree.FindBlockAndQC(block.Hash(), block.NumberU64())

	var validator *cbfttypes.ValidateNode
	if qc == nil || cbft.state.Epoch() == qc.Epoch {
		length := cbft.validatorPool.Len(block.NumberU64())
		currentProposer := cbft.state.ViewNumber() % uint64(length)
		validator, _ = cbft.validatorPool.GetValidatorByIndex(block.NumberU64(), uint32(currentProposer))
	} else {
		length := cbft.validatorPool.Len(block.NumberU64() + 1)
		currentProposer := cbft.state.ViewNumber() % uint64(length)
		validator, _ = cbft.validatorPool.GetValidatorByIndex(block.NumberU64()+1, uint32(currentProposer))
	}

	return validator
}

func (cbft *Cbft) currentValidatorLen() int {
	block := cbft.state.HighestQCBlock()
	_, qc := cbft.blockTree.FindBlockAndQC(block.Hash(), block.NumberU64())

	length := 0
	if qc == nil || cbft.state.Epoch() == qc.Epoch {
		length = cbft.validatorPool.Len(block.NumberU64())
	} else {
		length = cbft.validatorPool.Len(block.NumberU64() + 1)
	}

	return length
}

func (cbft *Cbft) verifyConsensusMsg(msg ctypes.ConsensusMsg) (*cbfttypes.ValidateNode, error) {
	digest, err := msg.CannibalizeBytes()
	if err != nil {
		return nil, errors.Wrap(err, "get msg's cannibalize bytes failed")
	}

	// Verify consensus msg signature
	if err := cbft.validatorPool.Verify(msg.BlockNum(), msg.NodeIndex(), digest, msg.Sign()); err != nil {
		return nil, err
	}

	// Get validator of signer
	vnode, err := cbft.validatorPool.GetValidatorByIndex(msg.BlockNum(), msg.NodeIndex())

	if err != nil {
		return nil, errors.Wrap(err, "get validator failed")
	}

	var prepareQC *ctypes.QuorumCert

	switch cm := msg.(type) {
	case *protocols.PrepareBlock:
		proposer := cbft.currentProposer()
		if uint32(proposer.Index) != msg.NodeIndex() {
			return nil, fmt.Errorf("current proposer index:%d, prepare block author index:%d", proposer.Index, msg.NodeIndex())
		}
		// BlockNum equal 1, the parent's block is genesis, doesn't has prepareQC
		// BlockIndex is not equal 0, this is not first block of current proposer
		if cm.BlockNum() == 1 || cm.BlockIndex != 0 {
			return vnode, nil
		}
		prepareQC = cm.PrepareQC
		if cm.ViewChangeQC != nil {
			if err := cbft.verifyViewChangeQC(cm.ViewChangeQC); err != nil {
				return nil, err
			}
		}
	case *protocols.PrepareVote:
		if cm.BlockNum() == 1 {
			return vnode, nil
		}
		prepareQC = cm.ParentQC
	case *protocols.ViewChange:
		// Genesis block doesn't has prepareQC
		if cm.BlockNumber == 0 {
			return vnode, nil
		}
		prepareQC = cm.PrepareQC
	}

	if err := cbft.verifyPrepareQC(msg.Original(), prepareQC); err != nil {
		return nil, err
	}

	return vnode, nil
}

func (cbft *Cbft) Pause()  { utils.SetTrue(&cbft.syncing) }
func (cbft *Cbft) Resume() { utils.SetFalse(&cbft.syncing) }

func (cbft *Cbft) generatePrepareQC(votes map[uint32]*protocols.PrepareVote) *ctypes.QuorumCert {
	if len(votes) == 0 {
		return nil
	}

	var vote *protocols.PrepareVote

	for _, v := range votes {
		vote = v
	}

	// Validator set prepareQC is the same as highestQC
	total := cbft.validatorPool.Len(vote.BlockNum())

	vSet := utils.NewBitArray(uint32(total))
	vSet.SetIndex(vote.NodeIndex(), true)

	var aggSig bls.Sign
	if err := aggSig.Deserialize(vote.Sign()); err != nil {
		return nil
	}

	qc := &ctypes.QuorumCert{
		Epoch:        vote.Epoch,
		ViewNumber:   vote.ViewNumber,
		BlockHash:    vote.BlockHash,
		BlockNumber:  vote.BlockNumber,
		BlockIndex:   vote.BlockIndex,
		ValidatorSet: utils.NewBitArray(vSet.Size()),
	}
	for _, p := range votes {
		if p.NodeIndex() != vote.NodeIndex() {
			var sig bls.Sign
			err := sig.Deserialize(p.Sign())
			if err != nil {
				return nil
			}

			aggSig.Add(&sig)
			vSet.SetIndex(p.NodeIndex(), true)
		}
	}
	qc.Signature.SetBytes(aggSig.Serialize())
	qc.ValidatorSet.Update(vSet)
	log.Debug("Generate prepare qc", "hash", vote.BlockHash, "number", vote.BlockNumber, "qc", qc.String())
	return qc
}

func (cbft *Cbft) generateViewChangeQC(viewChanges map[uint32]*protocols.ViewChange) *ctypes.ViewChangeQC {
	type ViewChangeQC struct {
		cert   *ctypes.ViewChangeQuorumCert
		aggSig *bls.Sign
		ba     *utils.BitArray
	}

	total := uint32(cbft.validatorPool.Len(cbft.state.HighestQCBlock().NumberU64()))

	qcs := make(map[common.Hash]*ViewChangeQC)

	for _, v := range viewChanges {
		var aggSig bls.Sign
		if err := aggSig.Deserialize(v.Sign()); err != nil {
			return nil
		}

		if vc, ok := qcs[v.BlockHash]; !ok {
			blockEpoch, blockView := uint64(0), uint64(0)
			if v.PrepareQC != nil {
				blockEpoch, blockView = v.PrepareQC.Epoch, v.PrepareQC.ViewNumber
			}
			qc := &ViewChangeQC{
				cert: &ctypes.ViewChangeQuorumCert{
					Epoch:           v.Epoch,
					ViewNumber:      v.ViewNumber,
					BlockHash:       v.BlockHash,
					BlockNumber:     v.BlockNumber,
					BlockEpoch:      blockEpoch,
					BlockViewNumber: blockView,
					ValidatorSet:    utils.NewBitArray(total),
				},
				aggSig: &aggSig,
				ba:     utils.NewBitArray(total),
			}
			qc.ba.SetIndex(v.NodeIndex(), true)
			qcs[v.BlockHash] = qc
		} else {
			vc.aggSig.Add(&aggSig)
			vc.ba.SetIndex(v.NodeIndex(), true)
		}
	}

	qc := &ctypes.ViewChangeQC{QCs: make([]*ctypes.ViewChangeQuorumCert, 0)}
	for _, q := range qcs {
		q.cert.Signature.SetBytes(q.aggSig.Serialize())
		q.cert.ValidatorSet.Update(q.ba)
		qc.QCs = append(qc.QCs, q.cert)
	}
	log.Debug("Generate view change qc", "qc", qc.String())
	return qc
}

func (cbft *Cbft) verifyPrepareQC(original uint64, qc *ctypes.QuorumCert) error {
	defer func(t time.Time) {
		cbft.log.Trace("Verify prepare qc", "qc", qc.String(), "duration", time.Since(t))
	}(time.Now())

	if original != qc.BlockNumber {
		return fmt.Errorf("verify prepare qc failed,not the corresponding qc,oriNum:%d,qcNum:%d", original, qc.BlockNumber)
	}
	var cb []byte
	var err error
	if cb, err = qc.CannibalizeBytes(); err != nil {
		return err
	}
	if err = cbft.validatorPool.VerifyAggSigByBA(qc.BlockNumber, qc.ValidatorSet, cb, qc.Signature.Bytes()); err != nil {
		return fmt.Errorf("verify prepare qc failed: %v", err)
	}
	return err
}

func (cbft *Cbft) verifyViewChangeQC(viewChangeQC *ctypes.ViewChangeQC) error {
	// check signature number
	threshold := cbft.threshold(cbft.validatorPool.Len(cbft.state.HighestQCBlock().NumberU64()))
	signsTotal := viewChangeQC.Len()
	if signsTotal < threshold {
		return fmt.Errorf("viewchange has small number of signature total:%d, threshold:%d", signsTotal, threshold)
	}

	var err error
	epoch := uint64(0)
	viewNumber := uint64(0)
	for i, vc := range viewChangeQC.QCs {
		// Check if it is the same view
		if i == 0 {
			epoch = vc.Epoch
			viewNumber = vc.ViewNumber
		} else if epoch != vc.Epoch || viewNumber != vc.ViewNumber {
			err = fmt.Errorf("has multiple view messages")
			break
		}
		var cb []byte
		if cb, err = vc.CannibalizeBytes(); err != nil {
			err = fmt.Errorf("get cannibalize bytes failed")
			break
		}

		if err = cbft.validatorPool.VerifyAggSigByBA(vc.BlockNumber, vc.ValidatorSet, cb, vc.Signature.Bytes()); err != nil {
			err = fmt.Errorf("verify viewchange qc failed:number:%d,validators:%s,msg:%s,signature:%s,err:%v",
				vc.BlockNumber, vc.ValidatorSet.String(), hexutil.Encode(cb), vc.Signature.String(), err)
			break
		}
	}

	return err
}

// NodeID returns the ID value of the current node
func (cbft *Cbft) NodeID() discover.NodeID {
	return cbft.config.Option.NodeID
}

func (cbft *Cbft) avgRTT() time.Duration {
	produceInterval := time.Duration(cbft.config.Sys.Period/uint64(cbft.config.Sys.Amount)) * time.Millisecond
	rtt := cbft.AvgLatency() * 2
	if rtt == 0 || rtt >= produceInterval {
		rtt = cbft.DefaultAvgLatency() * 2
	}
	return rtt
}
