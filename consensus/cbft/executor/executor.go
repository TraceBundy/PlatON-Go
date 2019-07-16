package executor

import (
	"errors"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
)

type BlockExecutor interface {
	//Execution block, you need to pass in the parent block to find the parent block state
	execute(block *types.Block, parent *types.Block) error
}

//Block execution results, including block hash, block number, error message
type BlockExecuteStatus struct {
	hash   common.Hash
	number uint64
	err    error
}

type AsyncBlockExecutor interface {
	BlockExecutor
	//Asynchronous acquisition block execution results
	executeStatus() chan<- BlockExecuteStatus
}

type executeTask struct {
	parent *types.Block
	block  *types.Block
}

type asyncExecutor struct {
	AsyncBlockExecutor

	executeFn consensus.Executor

	executeTasks   chan *executeTask
	executeResults chan BlockExecuteStatus

	closed chan struct{}
}

func NewAsyncExecutor(executeFn consensus.Executor) *asyncExecutor {
	exe := &asyncExecutor{
		executeFn:      executeFn,
		executeTasks:   make(chan *executeTask, 64),
		executeResults: make(chan BlockExecuteStatus, 64),
		closed:         make(chan struct{}),
	}

	go exe.loop()

	return exe
}

func (exe *asyncExecutor) stop() {
	close(exe.closed)
}

func (exe *asyncExecutor) execute(block *types.Block, parent *types.Block) error {
	return exe.newTask(block, parent)
}

func (exe *asyncExecutor) executeStatus() chan<- BlockExecuteStatus {
	return exe.executeResults
}

func (exe *asyncExecutor) newTask(block *types.Block, parent *types.Block) error {
	select {
	case exe.executeTasks <- &executeTask{parent: parent, block: block}:
		return nil
	default:
		return errors.New("execute task queue is full")
	}
}

func (exe *asyncExecutor) loop() {
	for {
		select {
		case <-exe.closed:
			return
		case task := <-exe.executeTasks:
			err := exe.executeFn(task.block, task.parent)
			exe.executeResults <- BlockExecuteStatus{
				hash:   task.block.Hash(),
				number: task.block.Number().Uint64(),
				err:    err,
			}
		}
	}
}
