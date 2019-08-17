package plugin

import (
	"bytes"
	"fmt"

	"github.com/PlatONnetwork/PlatON-Go/x/gov"

	"github.com/PlatONnetwork/PlatON-Go/common/mock"
	"github.com/PlatONnetwork/PlatON-Go/x/xcom"

	"math/big"
	"testing"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/core/snapshotdb"
	"github.com/PlatONnetwork/PlatON-Go/crypto/sha3"
	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"
	"github.com/PlatONnetwork/PlatON-Go/rlp"
)

var (
	statedb    xcom.StateDB
	snapdbTest snapshotdb.DB
)

func Init() {
	snapdbTest = snapshotdb.Instance()
	c := mock.NewChain(nil)
	statedb = c.StateDB
}

func TestGovDB_SetGetTxtProposal(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	proposal := getTxtProposal()
	if e := gov.SetProposal(proposal, statedb); e != nil {
		t.Errorf("set proposal error,%s", e)
	}

	if proposalGet, e := gov.GetProposal(proposal.ProposalID, statedb); e != nil {
		t.Errorf("get proposal error,%s", e)
	} else {
		if proposalGet.GetPIPID() != proposal.GetPIPID() {
			t.Fatalf("get proposal error,expect %s,get %s", proposal.GetPIPID(), proposalGet.GetPIPID())
		}
	}
}

func TestGovDB_SetGetVerProposal(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	proposal := getVerProposal(common.Hash{0x1})
	if e := gov.SetProposal(proposal, statedb); e != nil {
		t.Errorf("set proposal error,%s", e)
	}

	//var proposalGet  Proposal
	if proposalGet, e := gov.GetProposal(proposal.ProposalID, statedb); e != nil {
		t.Errorf("get proposal error,%s", e)
	} else {
		if proposalGet.GetPIPID() != proposal.GetPIPID() {
			t.Fatalf("get proposal error,expect %s,get %s", proposal.GetPIPID(), proposalGet.GetPIPID())
		}
	}
}

func TestGovDB_SetProposalT2Snapdb(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	var proposalIds []common.Hash
	var proposalIdsEnd []common.Hash
	var proposalIdsPre common.Hash

	snapdbTest := snapshotdb.Instance()
	defer snapdbTest.Clear()
	//create block
	blockhash, e := newblock(snapdbTest, big.NewInt(1))
	if e != nil {
		t.Fatalf("create block error ...%s", e)
	}

	totalLen := 10
	for i := 1; i <= totalLen; i++ {
		proposal := getVerProposal(common.Hash{byte(i)})
		if err := gov.AddVotingProposalID(blockhash, proposal.ProposalID); err != nil {
			t.Fatalf("add voting proposal failed...%s", err)
		}
		proposalIds = append(proposalIds, proposal.ProposalID)

		gov.SetProposal(proposal, statedb)
	}

	for i := 0; i < 2; i++ {
		if err := gov.MoveVotingProposalIDToEnd(blockhash, proposalIds[i], statedb); err != nil {
			t.Fatalf("move voting proposal to end failed...%s", err)
		} else {
			proposalIdsEnd = append(proposalIdsEnd, proposalIds[i])
			proposalIds = append(proposalIds[:i], proposalIds[i+1:]...)
		}
	}

	if err := gov.MoveVotingProposalIDToPreActive(blockhash, proposalIds[1]); err != nil {
		t.Fatalf("move voting proposal to pre active failed...%s", err)
	} else {
		proposalIdsPre = proposalIds[1]
		proposalIds = append(proposalIds[:1], proposalIds[2:]...)
	}

	if proposals, e := gov.GetProposalList(blockhash, statedb); e != nil {
		t.Fatalf("get proposal list error ,%s", e)
	} else {
		if len(proposals) != totalLen {
			t.Fatalf("get proposal list error ,expect len:%d,get len: %d", totalLen, len(proposals))
		}
	}

	if plist, e := gov.ListEndProposalID(blockhash); e != nil {
		t.Fatalf("list end propsal error,%s", e)
	} else {
		if len(plist) != len(proposalIdsEnd) {
			t.Fatalf("get end proposal list error ,expect len:%d,get len: %d", len(proposalIdsEnd), len(plist))
		}
	}
	if plist, e := gov.ListVotingProposal(blockhash); e != nil {
		t.Fatalf("list end propsal error,%s", e)
	} else {
		if len(plist) != len(proposalIds) {
			t.Fatalf("get voting proposal list error ,expect len:%d,get len: %d", len(proposalIds), len(plist))
		}
	}
	if p, e := gov.GetPreActiveProposalID(blockhash); e != nil {
		t.Fatalf("list end propsal error,%s", e)
	} else {
		if p != proposalIdsPre {
			t.Fatalf("get pre-active proposal error ,expect:%d,get: %d", proposalIdsPre, p)
		}
	}

	if err := commitBlock(snapdbTest, blockhash); err != nil {
		t.Fatalf("commit block error..%s", err)
	}
}

func TestGovDB_SetPreActiveVersion(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	version := uint32(32)
	//proposal := getVerProposal(common.Hash{0x1})
	if err := gov.SetPreActiveVersion(version, statedb); err != nil {
		t.Fatalf("set pre-active version error...%s", err)
	}
	vget := gov.GetPreActiveVersion(statedb)
	if vget != version {
		t.Fatalf("get pre-active version error,expect version:%d,get version:%d", version, vget)
	}
}

func TestGovDB_GetPreActiveVersionNotExist(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	vget := gov.GetPreActiveVersion(statedb)
	t.Logf("get pre-active version error,get version:%d", vget)
}

func TestGovDB_SetActiveVersion(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	version := uint32(32)
	//proposal := getVerProposal(common.Hash{0x1})
	if err := gov.AddActiveVersion(version, 10000, statedb); err != nil {
		t.Fatalf("add active version error...%s", err)
	}
	vget := gov.GetCurrentActiveVersion(statedb)
	if vget != version {
		t.Fatalf("get current active version error,expect version:%d,get version:%d", version, vget)
	}
}

func TestGovDB_SetVote(t *testing.T) {
	Init()
	defer snapdbTest.Clear()

	proposal := getVerProposal(common.Hash{0x1})
	gov.SetProposal(proposal, statedb)

	for _, node := range nodeIdTests {
		if nil != gov.SetVote(proposal.ProposalID, node.VoteNodeID, node.VoteOption, statedb) {
			t.Fatalf("set vote error...")
		}
	}

	voteList, err := gov.ListVoteValue(proposal.GetProposalID(), statedb)
	if err != nil {
		t.Fatalf("get vote list error, expect count：%d,get count:%d", len(nodeIdTests), len(voteList))
	}

	if len(voteList) != len(nodeIdTests) {
		t.Fatalf("get vote list error, expect count：%d,get count:%d", len(nodeIdTests), len(voteList))
	}

	tallyResult := gov.TallyResult{
		ProposalID:    proposal.GetProposalID(),
		Yeas:          uint16(len(voteList)),
		Nays:          0,
		Abstentions:   0,
		AccuVerifiers: 1000,
		Status:        gov.Pass,
	}

	if err := gov.SetTallyResult(tallyResult, statedb); err != nil {
		t.Fatalf("set vote result error")
	}

	if result, e := gov.GetTallyResult(proposal.ProposalID, statedb); e != nil {
		t.Fatalf("get vote result error,%s", e)
	} else {
		if result.Status != tallyResult.Status {
			t.Fatalf("get vote result error")
		}
	}
}

func TestGovDB_AddActiveNode(t *testing.T) {

	Init()
	defer snapdbTest.Clear()

	snapdbTest := snapshotdb.Instance()
	defer snapdbTest.Clear()
	//create block
	blockhash, e := newblock(snapdbTest, big.NewInt(1))
	if e != nil {
		t.Fatalf("create block error ...%s", e)
	}
	proposal := getTxtProposal()

	for _, node := range nodeIdTests {
		if err := gov.AddActiveNode(blockhash, proposal.ProposalID, node.VoteNodeID); err != nil {
			t.Fatalf("add active node error...%s", err)
		}
	}

	if ids, err := gov.GetActiveNodeList(blockhash, proposal.ProposalID); err != nil {
		t.Fatalf("get active node list error...%s", err)
	} else {
		if len(ids) != len(nodeIdTests) {
			t.Fatalf(" get active node list error, expect len:%d,get len:%d", len(nodeIdTests), len(ids))
		}
	}

	if err := gov.ClearActiveNodes(blockhash, proposal.ProposalID); err != nil {
		t.Fatalf("clear active node list error...%s", err)
	} else {
		if ids, err := gov.GetActiveNodeList(blockhash, proposal.ProposalID); err != nil {
			t.Fatalf("get active node list after clear error...%s", err)
		} else {
			if len(ids) != 0 {
				t.Fatalf(" get active node list after clear error, expect len:0,get len:%d", len(ids))
			}
		}
	}
}

func newblock(snapdbTest snapshotdb.DB, blockNumber *big.Int) (common.Hash, error) {

	recognizedHash := generateHash("recognizedHash")

	commitHash := recognizedHash
	if err := snapdbTest.NewBlock(blockNumber, common.Hash{}, commitHash); err != nil {
		return common.Hash{}, err
	}

	if err := snapdbTest.Put(commitHash, []byte("wu"), []byte("wei")); err != nil {
		return common.Hash{}, err
	}

	get, err := snapdbTest.Get(commitHash, []byte("wu"))
	if err != nil {
		return common.Hash{}, err
	}
	fmt.Printf("get result :%s", get)

	return commitHash, nil
}

func commitBlock(snapdbTest snapshotdb.DB, blockhash common.Hash) error {
	return snapdbTest.Commit(blockhash)
}

func getTxtProposal() *gov.TextProposal {
	return &gov.TextProposal{
		ProposalID:   common.Hash{0x01},
		ProposalType: gov.Text,
		PIPID:        "em。。。。",
		SubmitBlock:  uint64(1000),
		Proposer:     discover.NodeID{},
	}
}

func getVerProposal(proposalId common.Hash) *gov.VersionProposal {
	return &gov.VersionProposal{
		ProposalID:      proposalId,
		ProposalType:    gov.Version,
		PIPID:           "em。。。。",
		SubmitBlock:     uint64(1000),
		EndVotingRounds: uint64(10000000),
		Proposer:        discover.NodeID{},
		NewVersion:      32,
		ActiveBlock:     uint64(562222),
	}
}

var nodeIdTests = []gov.VoteValue{
	{
		VoteNodeID: discover.MustHexID("0x1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
		VoteOption: gov.Yes,
	},
	{
		VoteNodeID: discover.MustHexID("0x1dd8d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
		VoteOption: gov.Yes,
	},
	{
		VoteNodeID: discover.MustHexID("0x1dd7d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
		VoteOption: gov.Yes,
	},
	{
		VoteNodeID: discover.MustHexID("0x1dd6d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
		VoteOption: gov.Yes,
	},
	{
		VoteNodeID: discover.MustHexID("0x1dd5d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439"),
		VoteOption: gov.Yes,
	},
}

func generateHash(n string) common.Hash {
	var buf bytes.Buffer
	buf.Write([]byte(n))
	return rlpHash(buf.Bytes())
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
