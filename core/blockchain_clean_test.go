package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/crypto"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
	"github.com/PlatONnetwork/PlatON-Go/consensus"
	"github.com/PlatONnetwork/PlatON-Go/core/snapshotdb"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/ethdb"
	"github.com/PlatONnetwork/PlatON-Go/trie"
	"github.com/stretchr/testify/assert"
)

var (
	testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddress = crypto.PubkeyToAddress(testKey.PublicKey)

	securePreifx = []byte("secure-key-")
)

func randBytes(n int) []byte {
	r := make([]byte, n)
	rand.Read(r)
	return r
}

func TestScanStateTrie(t *testing.T) {
	memdb := ethdb.NewMemDatabase()
	stateDB := state.NewDatabase(memdb)
	s, _ := state.New(common.Hash{}, stateDB)
	triedb := stateDB.TrieDB()
	kv := make(map[string][]byte)

	root := common.Hash{}
	//start := time.Now()
	k, v := randBytes(32), randBytes(32)
	//fmt.Println(hexutil.Encode(k), hexutil.Encode(v))
	//start = time.Now()
	for i := 1; i < 3000; i++ {
		addr := common.Address{byte(i + 1)}
		for j := 0; j < 10; j++ {
			s.AddBalance(addr, big.NewInt(int64(i+1)))
			binary.BigEndian.PutUint32(k, uint32(i+j))
			binary.BigEndian.PutUint32(v, uint32(i+j))
			s.SetState(addr, k, v)
			kv[string(k)] = v
			//fmt.Println("v", hexutil.Encode(crypto.Keccak256(v)), "value", hexutil.Encode(v), "addr", addr.String())
		}
	}
	var err error
	root, err = s.Commit(true)
	if err != nil {
		t.Fatal(err)
	}
	triedb.Commit(root, false, nil)
	//fmt.Println("commit db", time.Since(start), "memdb", len(memdb.Keys()), "kv", len(kv))

	delDB := make([][]byte, 0, 100)
	delKv := make([][]byte, 0, 100)
	onNode := func(hash []byte) {
		hash = append(trie.MerklePrefix, hash...)
		v, _ := memdb.Get(hash)
		if v == nil {
			t.Fatal(fmt.Sprintf("%s", hexutil.Encode(hash)))
		}
		delDB = append(delDB, hash)
	}
	onValue := func(hash []byte) {
		hash = append(trie.MerklePrefix, hash...)
		v, _ := memdb.Get(hash)
		if v == nil {
			for i, k := range memdb.Keys() {
				fmt.Println(i, hexutil.Encode(k))
			}
			t.Fatal(fmt.Sprintf("%s", hexutil.Encode(hash)))
		}
		delKv = append(delKv, hash)
	}
	onPreImage := func(hash []byte) {
		hash = append(trie.SecureKeyPrefix, hash...)
		if value, _ := memdb.Get(hash); value != nil {
			delete(kv, string(value))
		} else {
			t.Fatal(fmt.Sprintf("%s", hexutil.Encode(hash)))
		}
		delDB = append(delDB, hash)
	}

	//start = time.Now()
	if err := ScanStateTrie(root, triedb, onNode, onValue, onPreImage); err != nil {
		t.Fatal(err)
	}

	for _, k := range delDB {
		memdb.Delete(k)
	}
	for _, k := range delKv {
		memdb.Delete(k)
	}
	//fmt.Println("memdb", len(memdb.Keys()), "kv", len(kv), "cost", time.Since(start))
	assert.Empty(t, memdb.Keys())
	assert.Empty(t, kv)
	for i, k := range memdb.Keys() {
		v, _ := memdb.Get(k)
		fmt.Println("commit", i, hexutil.Encode(k), "v", hexutil.Encode(v))
	}
}

func newBlockChainForTesting(db ethdb.Database) (*BlockChain, error) {
	buf, err := ioutil.ReadFile("../eth/downloader/testdata/platon.json")
	if err != nil {
		return nil, err
	}

	var gen Genesis
	if err := gen.UnmarshalJSON(buf); err != nil {
		return nil, err
	}

	gen.Alloc[testAddress] = GenesisAccount{
		Code:    nil,
		Storage: nil,
		Balance: big.NewInt(10000000000),
		Nonce:   0,
	}

	block, _ := gen.Commit(db, snapshotdb.Instance())

	return GenerateBlockChain(gen.Config, block, new(consensus.BftMock), db, 200, func(i int, block *BlockGen) {
		block.statedb.SetState(testAddress, []byte(fmt.Sprintf("abc_%d", i+1)), []byte(fmt.Sprintf("abccccccc_%d", i+1)))
	}), nil
}

func TestCleaner(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "platon")
	assert.Nil(t, err)
	defer os.RemoveAll(tmpDir)

	db, err := ethdb.NewLDBDatabase(tmpDir, 100, 1024)
	assert.Nil(t, err)

	blockchain, err := newBlockChainForTesting(db)
	assert.Nil(t, err)
	assert.NotNil(t, blockchain)

	cleaner := NewCleaner(blockchain, 100, time.Minute)
	cleaner.lastNumber = 0
	assert.NotNil(t, cleaner)
	assert.True(t, cleaner.NeedCleanup())
	cleaner.interval = 200
	assert.True(t, cleaner.NeedCleanup())
	cleaner.interval = 201
	assert.False(t, cleaner.NeedCleanup())

	cleaner.lastNumber = 0
	cleaner.cleanTimeout = time.Nanosecond
	cleaner.Cleanup()
	time.Sleep(100 * time.Millisecond)
	assert.True(t, cleaner.lastNumber == 0)

	cleaner.cleanTimeout = time.Minute
	cleaner.interval = 200
	cleaner.Cleanup()
	time.Sleep(500 * time.Millisecond) // Waiting cleanup finish
	assert.True(t, cleaner.lastNumber == 195)

	block := blockchain.GetBlockByNumber(188)
	_, err = blockchain.StateAt(block.Root())
	assert.NotNil(t, err)

	block = blockchain.GetBlockByNumber(196)
	statedb, _ := blockchain.StateAt(block.Root())
	assert.NotNil(t, statedb)
	buf := statedb.GetState(testAddress, []byte(fmt.Sprintf("abc_%d", block.NumberU64())))
	assert.Equal(t, string(buf), fmt.Sprintf("abccccccc_%d", block.NumberU64()))

	cleaner.Stop()

	// Test loading last number from database
	cleaner = NewCleaner(blockchain, 200, time.Minute)
	assert.Equal(t, cleaner.lastNumber, uint64(195))
}
