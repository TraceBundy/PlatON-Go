package cbft

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"reflect"
	"strconv"
	"time"
)

const (
	flagState = byte(1)
	flagStat  = byte(2)

	LOG_PREFIX = "OPENTRACE"
)

type Context struct {
	//TraceID represents globally unique ID of the trace, such view's timestamp
	TraceID uint64 `json:"trace_id"`

	// SpanID represents span ID that must be unique within its trace, such as peerID, blockNum, baseBlock
	// but does not have to be globally unique.
	SpanID string `json:"span_id"`

	// ParentID refers to the ID of the parent span.
	// Should be "" if the current span is a root span.
	ParentID string `json:"parent_id"`

	// Log type such as "state", "stat"
	Flags byte `json:"flags"`

	//message signer
	Creator string `json:"creator"`

	//local node
	Processor string `json:"processor"`
}

type Tag struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type LogRecord struct {
	Timestamp uint64      `json:"timestamp"`
	Log       interface{} `json:"log"`
}

type Span struct {
	Context      Context       `json:"context"`
	StartTime    time.Time     `json:"start_time"`
	DurationTime time.Duration `json:"duration_time"`
	Tags         []Tag         `json:"tags"`
	LogRecords   []LogRecord   `json:"log_records"`
	//operation name, such as message type
	OperationName string `json:"operation_name"`
}

var logBP Breakpoint

func init() {
	logBP = &defaultBreakpoint{
		prepareBP:    new(logPrepareBP),
		viewChangeBP: new(logViewChangeBP),
		syncBlockBP:  new(logSyncBlockBP),
		internalBP:   new(logInternalBP),
	}
}

type logPrepareBP struct {
}

func (bp logPrepareBP) ReceiveBlock(ctx context.Context, block *prepareBlock, cbft *Cbft) {
	log.Debug("ReceiveBlock", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) ReceiveVote(ctx context.Context, vote *prepareVote, cbft *Cbft) {
	tags := []Tag{
		{ Key: "action", Value: "receive", },
	}
	span, err := makeSpan(ctx, cbft, vote, tags)
	if err != nil {
		log.Error("ReceiveVote make span fail", "err", err)
		return
	}
	jsonSpan, err := json.Marshal(span)
	if err != nil {
		log.Error("ReceiveVote marshal span fail", "err", err)
		return
	}
	fmt.Println(string(jsonSpan))
	log.Info(LOG_PREFIX, "logs", string(jsonSpan))
}

func (bp logPrepareBP) AcceptBlock(ctx context.Context, block *prepareBlock, cbft *Cbft) {
	log.Debug("AcceptBlock", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) CacheBlock(ctx context.Context, block *prepareBlock, cbft *Cbft) {
	log.Debug("CacheBlock", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) DiscardBlock(ctx context.Context, block *prepareBlock, cbft *Cbft) {
	log.Debug("DiscardBlock", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) AcceptVote(ctx context.Context, vote *prepareVote, cbft *Cbft) {
	tags := []Tag{
		{ Key: "action", Value: "accept", },
	}
	span, err := makeSpan(ctx, cbft, vote, tags)
	if err != nil {
		log.Error("AcceptVote make span fail", "err", err)
		return
	}
	jsonSpan, err := json.Marshal(span)
	if err != nil {
		log.Error("AcceptVote marshal span to json fail", "err", err)
		return
	}
	log.Info(LOG_PREFIX, "logs", string(jsonSpan))
	//log.Debug("AcceptVote", "block", vote.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) CacheVote(ctx context.Context, vote *prepareVote, cbft *Cbft) {
	tags := []Tag{
		{ Key: "action", Value: "cache", },
	}
	span, err := makeSpan(ctx, cbft, vote, tags)
	if err != nil {
		log.Error("CacheVote make span fail", "err", err)
		return
	}
	jsonSpan, err := json.Marshal(span)
	if err != nil {
		log.Error("CacheVote marshal span to json fail", "err", err)
		return
	}
	log.Info(LOG_PREFIX, "logs", string(jsonSpan))
	//log.Debug("CacheVote", "block", vote.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) DiscardVote(ctx context.Context, vote *prepareVote, cbft *Cbft) {
	tags := []Tag{
		{ Key: "action", Value: "discard", },
	}
	span, err := makeSpan(ctx, cbft, vote, tags)
	if err != nil {
		log.Error("DiscardVote make span fail", "err", err)
		return
	}
	jsonSpan, err := json.Marshal(span)
	if err != nil {
		log.Error("DiscardVote marshal span to json fail", "err", err)
		return
	}
	log.Info(LOG_PREFIX, "logs", string(jsonSpan))
	//log.Debug("DiscardVote", "block", vote.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) SendPrepareVote(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	// 执行成功后会发送
	log.Debug("SendPrepareVote", "block", ext.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) InvalidBlock(ctx context.Context, block *prepareBlock, err error, cbft *Cbft) {
	log.Debug("InvalidBlock", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) InvalidVote(ctx context.Context, vote *prepareVote, err error, cbft *Cbft) {
	tags := []Tag{
		{ Key: "action", Value: "invalid", },
	}
	span, err := makeSpan(ctx, cbft, vote, tags)
	if err != nil {
		log.Error("InvalidVote make span fail", "err", err)
		return
	}
	jsonSpan, err := json.Marshal(span)
	if err != nil {
		log.Error("InvalidVote marshal span fail", "err", err)
		return
	}
	log.Info(string(jsonSpan))
}

func (bp logPrepareBP) InvalidViewChangeVote(ctx context.Context, block *prepareBlock, err error, cbft *Cbft) {
	log.Debug("InvalidViewChangeVote", "block", block.String(), "cbft", cbft.String())
}

func (bp logPrepareBP) TwoThirdVotes(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("TwoThirdVotes", "block", ext.String(), "cbft", cbft.String())
}

type logViewChangeBP struct {
}

func (bp logViewChangeBP) ReceiveViewChange(ctx context.Context, view *viewChange, cbft *Cbft) {
	log.Debug("ReceiveViewChange", "block", view.String(), "cbft", cbft.String())
}

func (bp logViewChangeBP) ReceiveViewChangeVote(ctx context.Context, vote *viewChangeVote, cbft *Cbft) {
	log.Debug("ReceiveViewChangeVote", "vote", vote.String(), "cbft", cbft.String())
}

func (bp logViewChangeBP) InvalidViewChange(ctx context.Context, view *viewChange, err error, cbft *Cbft) {
	log.Debug("InvalidViewChange", "view", view.String(), "cbft", cbft.String())
}

func (bp logViewChangeBP) InvalidViewChangeVote(ctx context.Context, view *viewChangeVote, err error, cbft *Cbft) {
	log.Debug("InvalidViewChangeVote", "view", view.String(), "cbft", cbft.String())
}

func (bp logViewChangeBP) InvalidViewChangeBlock(ctx context.Context, view *viewChange, cbft *Cbft) {
	log.Debug("InvalidViewChangeBlock", "view", view.String(), "cbft", cbft.String())
}

func (bp logViewChangeBP) TwoThirdViewChangeVotes(ctx context.Context, cbft *Cbft) {
	log.Debug("TwoThirdViewChangeVotes", "cbft", cbft.String())
}

func (bp logViewChangeBP) SendViewChangeVote(ctx context.Context, vote *viewChangeVote, cbft *Cbft) {
	log.Debug("SendViewChangeVote", "vote", vote.String(), "cbft", cbft.String())

}

func (bp logViewChangeBP) ViewChangeTimeout(ctx context.Context, cbft *Cbft) {
	log.Debug("ViewChangeTimeout", "cbft", cbft.String())

}

type logSyncBlockBP struct {
}

func (bp logSyncBlockBP) SyncBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("SyncBlock", "block", ext.String(), "cbft", cbft.String())

}

func (bp logSyncBlockBP) InvalidBlock(ctx context.Context, ext *BlockExt, err error, cbft *Cbft) {
	log.Debug("InvalidBlock", "block", ext.String(), "cbft", cbft.String())

}

type logInternalBP struct {
}

func (bp logInternalBP) ExecuteBlock(ctx context.Context, hash common.Hash, number uint64, elapse time.Duration) {
	log.Debug("ExecuteBlock", "hash", hash, "number", number, "elapse", elapse.Seconds())
}

func (bp logInternalBP) InvalidBlock(ctx context.Context, hash common.Hash, number uint64, err error) {
	log.Debug("InvalidBlock", "hash", hash, number, number)

}

func (bp logInternalBP) ForkedResetTxPool(ctx context.Context, newHeader *types.Header, injectBlock types.Blocks, elapse time.Duration, cbft *Cbft) {
	log.Debug("ForkedResetTxPool",
		"newHeader", fmt.Sprintf("[hash:%s, number:%d]", newHeader.Hash().TerminalString(), newHeader.Number.Uint64()),
		"block", injectBlock.String(), "elapse", elapse.Seconds(), "cbft", cbft.String())

}

func (bp logInternalBP) ResetTxPool(ctx context.Context, ext *BlockExt, elapse time.Duration, cbft *Cbft) {
	log.Debug("ResetTxPool", "block", ext.String(), "elapse", elapse.Seconds(), "cbft", cbft.String())

}

func (bp logInternalBP) NewConfirmedBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewConfirmedBlock", "block", ext.String(), "cbft", cbft.String())

}

func (bp logInternalBP) NewLogicalBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewLogicalBlock", "block", ext.String(), "cbft", cbft.String())

}

func (bp logInternalBP) NewRootBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewRootBlock", "block", ext.String(), "cbft", cbft.String())
}

func (bp logInternalBP) NewHighestConfirmedBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewHighestConfirmedBlock", "block", ext.String(), "cbft", cbft.String())
}

func (bp logInternalBP) NewHighestLogicalBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewHighestLogicalBlock", "block", ext.String(), "cbft", cbft.String())
}

func (bp logInternalBP) NewHighestRootBlock(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("NewHighestRootBlock", "block", ext.String(), "cbft", cbft.String())
}

func (bp logInternalBP) SwitchView(ctx context.Context, view *viewChange) {
	log.Debug("SwitchView", "view", view.String())

}

func (bp logInternalBP) Seal(ctx context.Context, ext *BlockExt, cbft *Cbft) {
	log.Debug("SwitchView", "block", ext.String(), "cbft", cbft.String())
}

func makeSpan(ctx context.Context, cbft *Cbft, message interface{}, tag []Tag) (*Span, error) {
	from := ctx.Value("peer")
	if from != nil {
		tag = append(tag, Tag{ Key:"from", Value: from, })
	}
	context := Context{
		ParentID: cbft.config.NodeID.String(),
		Flags: flagState,
		Processor: cbft.config.NodeID.String(),
	}
	switch message.(type) {
	case *prepareVote:
		p := message.(*prepareVote)
		context.TraceID = p.Timestamp
		context.SpanID = strconv.FormatUint(p.Number, 10)
		context.Creator = p.ValidatorAddr.String()
	}
	span := Span{
		Context: context,
		StartTime: time.Now(),
		Tags: tag,
		OperationName: reflect.TypeOf(message).String(),
	}
	span.LogRecords = []LogRecord{
		{
			Timestamp: uint64(time.Now().Unix()),
			Log: message,
		},
	}
	span.DurationTime = time.Since(span.StartTime)
	return &span, nil
}