package cbft

import (
	"errors"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
)

type blockExecutor interface {
	//Execution block, you need to pass in the parent block to find the parent block state
	execute(block *types.Block, parent *types.Block) error
}

//Block execution results, including block hash, block number, error message
type blockExecuteStatus struct {
	hash   common.Hash
	number uint64
	err    error
}

type asyncBlockExecutor interface {
	blockExecutor
	//Asynchronous acquisition block execution results
	executeStatus() chan<- blockExecuteStatus
}

type executeTask struct {
	parent *types.Block
	block  *types.Block
}

type asyncExecutor struct {
	asyncBlockExecutor

	executeFn consensus.Executor

	executeTasks   chan *executeTask
	executeResults chan blockExecuteStatus

	closed chan struct{}
}

func NewAsyncExecutor(executeFn consensus.Executor) *asyncExecutor {
	exe := &asyncExecutor{
		executeFn:      executeFn,
		executeTasks:   make(chan *executeTask, 64),
		executeResults: make(chan blockExecuteStatus, 64),
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

func (exe *asyncExecutor) executeStatus() chan<- blockExecuteStatus {
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
			exe.executeResults <- blockExecuteStatus{
				hash:   task.block.Hash(),
				number: task.block.Number().Uint64(),
				err:    err,
			}
		}
	}
}
