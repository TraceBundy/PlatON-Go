/**********************定义*********************************
内置合约地址：
0x1000..0011		候选池内置合约
0x1000..0012		选票池内置合约
0x1000..0010 + x	其他定义的内置合约

交易data字段定义：
data = rlp(type [8]byte, funcname string, parma1 []byte, parma2 []byte, ...)

候选池合约：
0x11 + "funcname" + parmas

选票池合约：
0x12 + "funcname" + parmas

其他合约：
(0x10+x) + "funcname" + parmas

**********************定义*********************************/
package vm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/byteutil"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"
	"github.com/PlatONnetwork/PlatON-Go/params"
	"github.com/PlatONnetwork/PlatON-Go/rlp"
	"math/big"
	"reflect"
)

//error def
var (
	ErrOwnerNotonly     = errors.New("Node ID cannot bind multiple owners")
	ErrPermissionDenied = errors.New("Transaction from address permission denied")
	ErrDepositEmpyt     = errors.New("Deposit balance not zero")
	ErrWithdrawEmpyt    = errors.New("No withdrawal amount")
	ErrParamsRlpDecode  = errors.New("Rlp decode faile")
	ErrParamsBaselen    = errors.New("Params Base length does not match")
	ErrParamsLen        = errors.New("Params length does not match")
	ErrUndefFunction    = errors.New("Undefined function")
	ErrCandidateEmpyt   = errors.New("CandidatePool is nil")
	ErrCallRecode       = errors.New("Call recode error, panic...")
)

const (
	CandidateDepositEvent       = "CandidateDepositEvent"
	CandidateApplyWithdrawEvent = "CandidateApplyWithdrawEvent"
	CandidateWithdrawEvent      = "CandidateWithdrawEvent"
	SetCandidateExtraEvent      = "SetCandidateExtraEvent"
)

var PrecompiledContractsPpos = map[common.Address]PrecompiledContract{
	common.CandidateAddr: &candidateContract{},
}

type ResultCommon struct {
	Ret    bool
	ErrMsg string
}

type candidatePool interface {
	SetCandidate(state StateDB, nodeId discover.NodeID, can *types.Candidate) error
	GetCandidate(state StateDB, nodeId discover.NodeID) (*types.Candidate, error)
	WithdrawCandidate(state StateDB, nodeId discover.NodeID, price, blockNumber *big.Int) error
	GetChosens(state StateDB) []*types.Candidate
	GetChairpersons(state StateDB) []*types.Candidate
	GetDefeat(state StateDB, nodeId discover.NodeID) ([]*types.Candidate, error)
	IsDefeat(state StateDB, nodeId discover.NodeID) (bool, error)
	RefundBalance(state StateDB, nodeId discover.NodeID, blockNumber *big.Int) error
	GetOwner(state StateDB, nodeId discover.NodeID) common.Address
	SetCandidateExtra(state StateDB, nodeId discover.NodeID, extra string) error
	GetRefundInterval() uint64
}

type candidateContract struct {
	contract *Contract
	evm      *EVM
}

func (c *candidateContract) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *candidateContract) Run(input []byte) ([]byte, error) {

	//debug
	c.logInfo("candidatePool Run==> ", "input: ", hex.EncodeToString(input))

	defer func() {
		if err := recover(); nil != err {
			// catch call panic
			c.logError("Run Err==> ", "ErrCallRecode: ", ErrCallRecode.Error(), "err", fmt.Sprint(err))
		}
	}()
	var command = map[string]interface{}{
		"CandidateDetails":       c.CandidateDetails,
		"CandidateApplyWithdraw": c.CandidateApplyWithdraw,
		"CandidateDeposit":       c.CandidateDeposit,
		"CandidateList":          c.CandidateList,
		"CandidateWithdraw":      c.CandidateWithdraw,
		"SetCandidateExtra":      c.SetCandidateExtra,
		"CandidateWithdrawInfos": c.CandidateWithdrawInfos,
		"VerifiersList":          c.VerifiersList,
	}
	var source [][]byte
	if err := rlp.Decode(bytes.NewReader(input), &source); err != nil {
		c.logError("Run Err==> ", err.Error())
		return nil, ErrParamsRlpDecode
	}
	//check
	if len(source) < 2 {
		c.logError("Run Err==> ", "ErrParamsBaselen: ", ErrParamsBaselen.Error())
		return nil, ErrParamsBaselen
	}
	if c.evm.CandidatePool == nil {
		c.logError("Run Err==> ", "ErrCandidateEmpyt: ", ErrCandidateEmpyt.Error())
		return nil, ErrCandidateEmpyt
	}
	// get func and param list
	if _, ok := command[byteutil.BytesToString(source[1])]; !ok {
		c.logError("Run Err==> ", "ErrUndefFunction: ", ErrUndefFunction.Error())
		return nil, ErrUndefFunction
	}
	funcValue := command[byteutil.BytesToString(source[1])]
	paramList := reflect.TypeOf(funcValue)
	paramNum := paramList.NumIn()
	// var param []interface{}
	params := make([]reflect.Value, paramNum)
	if paramNum != len(source)-2 {
		c.logError("Run Err==> ", "ErrParamsLen: ", ErrParamsLen.Error())
		return nil, ErrParamsLen
	}
	for i := 0; i < paramNum; i++ {
		targetType := paramList.In(i).String()
		originByte := []reflect.Value{reflect.ValueOf(source[i+2])}
		params[i] = reflect.ValueOf(byteutil.Command[targetType]).Call(originByte)[0]
	}
	// call func
	result := reflect.ValueOf(funcValue).Call(params)
	c.logInfo("Run==> ", "result[0]: ", result[0].Bytes())
	if _, errOk := result[1].Interface().(error); !errOk {
		return result[0].Bytes(), nil
	}
	c.logError("Run Err==>", "err", result[1].Interface().(error).Error())
	return result[0].Bytes(), result[1].Interface().(error)
}

//Candidate Application && Increase Quality Deposit
func (c *candidateContract) CandidateDeposit(nodeId discover.NodeID, owner common.Address, fee uint64, host, port, extra string) ([]byte, error) {
	//debug
	deposit := c.contract.value
	txHash := c.evm.StateDB.TxHash()
	txIdx := c.evm.StateDB.TxIdx()
	height := c.evm.Context.BlockNumber
	from := c.contract.caller.Address()
	c.logInfo("CandidateDeposit==> ", "nodeId: ", nodeId.String(), " owner: ", owner.Hex(), " deposit: ", deposit,
		"  fee: ", fee, " txhash: ", txHash.Hex(), " txIdx: ", txIdx, " height: ", height, " from: ", from.Hex(),
		" host: ", host, " port: ", port, " extra: ", extra)
	//todo
	if deposit.Cmp(big.NewInt(0)) < 1 {
		r := ResultCommon{false, ErrDepositEmpyt.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateDepositEvent, string(data))
		return nil, ErrDepositEmpyt
	}
	can, err := c.evm.CandidatePool.GetCandidate(c.evm.StateDB, nodeId)
	if err != nil {
		c.logError("CandidateDeposit Err==> ", "err: ", err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateDepositEvent, string(data))
		return nil, err
	}
	var alldeposit *big.Int
	if can != nil {
		if ok := bytes.Equal(can.Owner.Bytes(), owner.Bytes()); !ok {
			c.logError("CandidateDeposit Err==> ", "err: ",ErrOwnerNotonly.Error())
			r := ResultCommon{false, err.Error()}
			data, _ := json.Marshal(r)
			c.addLog(CandidateDepositEvent, string(data))
			return nil, ErrOwnerNotonly
		}
		alldeposit = new(big.Int).Add(can.Deposit, deposit)
		c.logInfo("CandidateDeposit==> ", "alldeposit: ", alldeposit, " can.Deposit: ", can.Deposit, " deposit: ", deposit)
	} else {
		alldeposit = deposit
	}
	canDeposit := types.Candidate{
		alldeposit,
		height,
		txIdx,
		nodeId,
		host,
		port,
		owner,
		from,
		extra,
		fee,
	}
	c.logInfo("CandidateDeposit==> ", "canDeposit: ", canDeposit)
	if err = c.evm.CandidatePool.SetCandidate(c.evm.StateDB, nodeId, &canDeposit); err != nil {
		//rollback transaction
		//......
		c.logError("CandidateDeposit Err==> ", "SetCandidate return err: ", err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateDepositEvent, string(data))
		return nil, err
	}
	r := ResultCommon{true, "success"}
	data, _ := json.Marshal(r)
	c.addLog(CandidateDepositEvent, string(data))
	c.logInfo("CandidateDeposit==> ", "json: ", string(data))
	return nil, nil
}

//Apply for a refund of the deposit
func (c *candidateContract) CandidateApplyWithdraw(nodeId discover.NodeID, withdraw *big.Int) ([]byte, error) {
	//debug
	txHash := c.evm.StateDB.TxHash()
	from := c.contract.caller.Address()
	height := c.evm.Context.BlockNumber
	c.logInfo("CandidateApplyWithdraw==> ", "nodeId: ", nodeId.String(), " from: ", from.Hex(), " txHash: ", txHash.Hex(), " withdraw: ", withdraw, " height: ", height)
	//todo
	can, err := c.evm.CandidatePool.GetCandidate(c.evm.StateDB, nodeId)
	if err != nil {
		c.logError("CandidateApplyWithdraw Err==> ", "err", err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateApplyWithdrawEvent, string(data))
		return nil, err
	}
	if can.Deposit.Cmp(big.NewInt(0)) < 1 {
		r := ResultCommon{false, ErrWithdrawEmpyt.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateApplyWithdrawEvent, string(data))
		return nil, ErrWithdrawEmpyt
	}
	if ok := bytes.Equal(can.Owner.Bytes(), from.Bytes()); !ok {
		c.logError("CandidateApplyWithdraw Err==> ", "err",ErrPermissionDenied.Error())
		r := ResultCommon{false, ErrPermissionDenied.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateApplyWithdrawEvent, string(data))
		return nil, ErrPermissionDenied
	}
	if withdraw.Cmp(can.Deposit) > 0 {
		withdraw = can.Deposit
	}
	if err := c.evm.CandidatePool.WithdrawCandidate(c.evm.StateDB, nodeId, withdraw, height); err != nil {
		c.logError("CandidateApplyWithdraw Err==> ", "err",err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateApplyWithdrawEvent, string(data))
		return nil, err
	}
	r := ResultCommon{true, "success"}
	data, _ := json.Marshal(r)
	c.addLog(CandidateApplyWithdrawEvent, string(data))
	c.logInfo("CandidateApplyWithdraw==> ", "json: ", string(data))
	return nil, nil
}

//Deposit withdrawal
func (c *candidateContract) CandidateWithdraw(nodeId discover.NodeID) ([]byte, error) {
	//debug
	txHash := c.evm.StateDB.TxHash()
	height := c.evm.Context.BlockNumber
	c.logInfo("CandidateWithdraw==> ", "nodeId: ", nodeId.String(), " height: ", height, " txHash: ", txHash.Hex())
	//todo
	if err := c.evm.CandidatePool.RefundBalance(c.evm.StateDB, nodeId, height); err != nil {
		c.logError("CandidateWithdraw Err==> ", "err", err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(CandidateWithdrawEvent, string(data))
		return nil, err
	}
	//return
	r := ResultCommon{true, "success"}
	data, _ := json.Marshal(r)
	c.addLog(CandidateWithdrawEvent, string(data))
	c.logInfo("CandidateWithdraw==> ", "json: ", string(data))
	return nil, nil
}

//Get the refund history you have applied for
func (c *candidateContract) CandidateWithdrawInfos(nodeId discover.NodeID) ([]byte, error) {
	//debug
	c.logInfo("CandidateWithdrawInfos==> ", "nodeId: ", nodeId.String())
	//todo
	infos, err := c.evm.CandidatePool.GetDefeat(c.evm.StateDB, nodeId)
	if err != nil {
		c.logError("CandidateWithdrawInfos Err==> ", "err", err.Error())
		return nil, err
	}
	//return
	type WithdrawInfo struct {
		Balance        *big.Int
		LockNumber     *big.Int
		LockBlockCycle uint64
	}
	type WithdrawInfos struct {
		Ret    bool
		ErrMsg string
		Infos  []WithdrawInfo
	}
	r := WithdrawInfos{true, "success", make([]WithdrawInfo, len(infos))}
	for i, v := range infos {
		r.Infos[i] = WithdrawInfo{v.Deposit, v.BlockNumber, c.evm.CandidatePool.GetRefundInterval()}
	}
	data, _ := json.Marshal(r)
	sdata := DecodeResultStr(string(data))
	c.logInfo("CandidateWithdrawInfos==> ", "json: ", string(data))
	return sdata, nil
}

//Set up additional information
func (c *candidateContract) SetCandidateExtra(nodeId discover.NodeID, extra string) ([]byte, error) {
	//debug
	txHash := c.evm.StateDB.TxHash()
	from := c.contract.caller.Address()
	c.logInfo("SetCandidate==> ", "nodeId: ", nodeId.String(), " extra: ", extra, " from: ", from.Hex(), " txHash: ", txHash.Hex())
	//todo
	owner := c.evm.CandidatePool.GetOwner(c.evm.StateDB, nodeId)
	if ok := bytes.Equal(owner.Bytes(), from.Bytes()); !ok {
		c.logError("SetCandidate Err==> ", "err", ErrPermissionDenied.Error())
		r := ResultCommon{false, ErrPermissionDenied.Error()}
		data, _ := json.Marshal(r)
		c.addLog(SetCandidateExtraEvent, string(data))
		return nil, ErrPermissionDenied
	}
	if err := c.evm.CandidatePool.SetCandidateExtra(c.evm.StateDB, nodeId, extra); err != nil {
		c.logError("SetCandidate Err==> ", "err", err.Error())
		r := ResultCommon{false, err.Error()}
		data, _ := json.Marshal(r)
		c.addLog(SetCandidateExtraEvent, string(data))
		return nil, err
	}
	r := ResultCommon{true, "success"}
	data, _ := json.Marshal(r)
	c.addLog(SetCandidateExtraEvent, string(data))
	c.logInfo("SetCandidate==> ", "json: ", string(data))
	return nil, nil
}

//Get candidate details
func (c *candidateContract) CandidateDetails(nodeId discover.NodeID) ([]byte, error) {
	c.logInfo("CandidateDetails==> ", "nodeId: ", nodeId.String())
	candidate, err := c.evm.CandidatePool.GetCandidate(c.evm.StateDB, nodeId)
	if err != nil {
		c.logError("CandidateDetails Err==> ", "get CandidateDetails() occured error: ", err.Error())
		return nil, err
	}
	if nil == candidate {
		c.logError("CandidateDetails Err==> The candidate for the inquiry does not exist")
		return nil, nil
	}
	data, _ := json.Marshal(candidate)
	sdata := DecodeResultStr(string(data))
	c.logInfo("CandidateDetails==> ", "json: ", string(data), " []byte: ", sdata)
	return sdata, nil
}

//Get the current block candidate list 0~200
func (c *candidateContract) CandidateList() ([]byte, error) {
	c.logInfo("CandidateList==> into func CandidateList... ")
	arr := c.evm.CandidatePool.GetChosens(c.evm.StateDB)
	if nil == arr {
		c.logError("CandidateList Err==> The candidateList for the inquiry does not exist")
		return nil, nil
	}
	data, _ := json.Marshal(arr)
	sdata := DecodeResultStr(string(data))
	c.logInfo("CandidateList==>", "json: ", string(data), " []byte: ", sdata)
	return sdata, nil
}

//Get the current block round certifier list 25个
func (c *candidateContract) VerifiersList() ([]byte, error) {
	c.logInfo("VerifiersList==> into func VerifiersList... ")
	arr := c.evm.CandidatePool.GetChairpersons(c.evm.StateDB)
	if nil == arr {
		c.logError("VerifiersList Err==> The verifiersList for the inquiry does not exist")
		return nil, nil
	}
	data, _ := json.Marshal(arr)
	sdata := DecodeResultStr(string(data))
	c.logInfo("VerifiersList==> ", "json: ", string(data), " []byte: ", sdata)
	return sdata, nil
}

//transaction add event
func (c *candidateContract) addLog(event, data string) {
	var logdata [][]byte
	logdata = make([][]byte, 0)
	logdata = append(logdata, []byte(data))
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, logdata); err != nil {
		c.logError("addlog Err==> ", "rlp encode fail: ", err.Error())
	}
	c.evm.StateDB.AddLog(&types.Log{
		Address:     common.CandidateAddr,
		Topics:      []common.Hash{common.BytesToHash(crypto.Keccak256([]byte(event)))},
		Data:        buf.Bytes(),
		BlockNumber: c.evm.Context.BlockNumber.Uint64(),
	})
}

//debug log
func (c *candidateContract) logInfo(msg string, ctx ...interface{}) {
	log.Info(msg, ctx...)
	//args := []interface{}{msg}
	//args = append(args, ctx...)
	//fmt.Println(args...)
	/*if c.evm.vmConfig.ConsoleOutput {
		//console output
		args := []interface{}{msg}
		args = append(args, ctx...)
		fmt.Println(args...)
	}else {
		//log output
		log.Info(msg, ctx...)
	}*/
}
func (c *candidateContract) logError(msg string, ctx ...interface{}) {
	log.Error(msg, ctx...)
	//args := []interface{}{msg}
	//args = append(args, ctx...)
	//fmt.Println(args...)
	/*if c.evm.vmConfig.ConsoleOutput {
		//console output
		args := []interface{}{msg}
		args = append(args, ctx...)
		fmt.Println(args...)
	}else {
		//log output
		log.Error(msg, ctx...)
	}*/
}
func (c *candidateContract) logPrint(level log.Lvl, msg string, ctx ...interface{}) {
	if c.evm.vmConfig.ConsoleOutput {
		//console output
		args := make([]interface{}, len(ctx)+1)
		args[0] = msg
		for i, v := range ctx {
			args[i+1] = v
		}
		fmt.Println(args...)
	} else {
		//log output
		switch level {
		case log.LvlCrit:
			log.Crit(msg, ctx...)
		case log.LvlError:
			log.Error(msg, ctx...)
		case log.LvlWarn:
			log.Warn(msg, ctx...)
		case log.LvlInfo:
			log.Info(msg, ctx...)
		case log.LvlDebug:
			log.Debug(msg, ctx...)
		case log.LvlTrace:
			log.Trace(msg, ctx...)
		}
	}
}

//return string format
func DecodeResultStr(result string) []byte {
	// 0x0000000000000000000000000000000000000020
	// 00000000000000000000000000000000000000000d
	// 00000000000000000000000000000000000000000

	resultBytes := []byte(result)
	strHash := common.BytesToHash(common.Int32ToBytes(32))
	sizeHash := common.BytesToHash(common.Int64ToBytes(int64((len(resultBytes)))))
	var dataRealSize = len(resultBytes)
	if (dataRealSize % 32) != 0 {
		dataRealSize = dataRealSize + (32 - (dataRealSize % 32))
	}
	dataByt := make([]byte, dataRealSize)
	copy(dataByt[0:], resultBytes)

	finalData := make([]byte, 0)
	finalData = append(finalData, strHash.Bytes()...)
	finalData = append(finalData, sizeHash.Bytes()...)
	finalData = append(finalData, dataByt...)
	//encodedStr := hex.EncodeToString(finalData)
	//fmt.Println("finalData: ", encodedStr)
	return finalData
}
