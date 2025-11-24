package snapshotdb

import (
	"bytes"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/rlp"
	"github.com/PlatONnetwork/PlatON-Go/trie"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/util"
	"math/big"
)

type ArchiveSnapshot struct {
	trie        *trie.StateTrie
	blockNumber uint64
	kvHash      common.Hash
	vrfNonce    []byte
}

func (a *ArchiveSnapshot) Put(hash common.Hash, key, value []byte) error {
	a.trie.Update(key, value)
	return nil
}

func (a ArchiveSnapshot) NewBlock(blockNumber *big.Int, parentHash common.Hash, hash common.Hash) error {
	//TODO implement me
	panic("implement me")
}

func (a ArchiveSnapshot) Get(hash common.Hash, key []byte) ([]byte, error) {
	if bytes.HasPrefix(key, nonceStorageKey) {
		return a.vrfNonce, nil
	}
	return a.trie.Get(key), nil
}

func (a ArchiveSnapshot) GetFromCommittedBlock(key []byte) ([]byte, error) {
	return a.trie.Get(key), nil
}

func (a ArchiveSnapshot) Del(hash common.Hash, key []byte) error {
	a.trie.Delete(key)
	return nil
}

func (a ArchiveSnapshot) Has(hash common.Hash, key []byte) (bool, error) {
	return len(a.trie.Get(key)) != 0, nil
}

func (a ArchiveSnapshot) Flush(hash common.Hash, blocknumber *big.Int) error {
	return nil
}

func (a ArchiveSnapshot) Ranking(hash common.Hash, key []byte, ranges int) iterator.Iterator {
	//TODO implement me
	panic("implement me")
}

func (a ArchiveSnapshot) WalkBaseDB(slice *util.Range, f func(num *big.Int, iter iterator.Iterator) error) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) WalkDB(num uint64, f func(baseBlock uint64, iter iterator.Iterator, blocks []rlp.RawValue) error) error {
	panic("unsupported")

}

func (a ArchiveSnapshot) Commit(hash common.Hash) error {
	//do nothing
	return nil
}

func (a ArchiveSnapshot) Clear() error {
	//do nothing
	return nil
}

func (a ArchiveSnapshot) PutBaseDB(key, value []byte) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) GetBaseDB(key []byte) ([]byte, error) {
	panic("unsupported")
}

func (a ArchiveSnapshot) DelBaseDB(key []byte) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) WriteBaseDB(kvs [][2][]byte) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) WriteBaseDBWithBlock(current *types.Header, blocks []BlockData) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) SetCurrent(highestHash common.Hash, base, height big.Int) error {
	panic("unsupported")
}

func (a ArchiveSnapshot) GetCurrent() *current {
	panic("unsupported")
}

func (a *ArchiveSnapshot) GetLastKVHash(blockHash common.Hash) []byte {
	return a.kvHash.Bytes()
}

func (a *ArchiveSnapshot) BaseNum() (*big.Int, error) {
	panic("unsupported")
}

func (a ArchiveSnapshot) Close() error {
	return nil
}

func (a ArchiveSnapshot) Compaction() error {
	return nil
}

func (a ArchiveSnapshot) SetEmpty() error {
	panic("unsupported")
}

func (a ArchiveSnapshot) RevertToSnapshot(hash common.Hash, revid int) {
	//do nothind
}

func (a ArchiveSnapshot) Snapshot(hash common.Hash) int {
	return 0
}
