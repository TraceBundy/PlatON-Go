package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/ethdb"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
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
		v, _ := memdb.Get(hash)
		if v == nil {
			t.Fatal(fmt.Sprintf("%s", hexutil.Encode(hash)))
		}
		delDB = append(delDB, hash)
	}
	onValue := func(hash []byte) {
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
