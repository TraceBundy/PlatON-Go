package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
	"github.com/PlatONnetwork/PlatON-Go/core/rawdb"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/ethdb"
	"github.com/PlatONnetwork/PlatON-Go/event"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/PlatONnetwork/PlatON-Go/rlp"
	"github.com/PlatONnetwork/PlatON-Go/trie"
	"github.com/willf/bloom"
)

var (
	emptyState = crypto.Keccak256Hash(nil)

	lastNumberKey = []byte("last-clean-number")

	minCleanTimeout = time.Minute

	cleanDistance uint64 = 5
	idleState     int32  = 0
	cleaningState int32  = 1
	maxKeyCount   uint   = 10000000
)

type keyCallback func([]byte)

type CleanupEvent struct {
	Number uint64
}

type CleanBatch struct {
	lock  sync.Mutex
	batch ethdb.Batch
}

func (cb *CleanBatch) Delete(key []byte) error {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	return cb.batch.Delete(key)
}

func (cb *CleanBatch) ValueSize() int {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	return cb.batch.ValueSize()
}

func (cb *CleanBatch) WriteAndRest() error {
	cb.lock.Lock()
	defer cb.lock.Unlock()
	if err := cb.batch.Write(); err != nil {
		cb.batch.Reset()
		return err
	}
	cb.batch.Reset()
	return nil
}

type Cleaner struct {
	cleaning     int32
	interval     uint64
	lastNumber   uint64
	cleanTimeout time.Duration

	exit      chan struct{}
	cleanFeed event.Feed
	scope     event.SubscriptionScope
	cleanCh   chan *CleanupEvent

	batch      CleanBatch
	lock       sync.RWMutex
	filter     *bloom.BloomFilter
	blockchain *BlockChain
}

func NewCleaner(blockchain *BlockChain, interval uint64, cleanTimeout time.Duration) *Cleaner {
	c := &Cleaner{
		interval:     interval,
		lastNumber:   0,
		cleanTimeout: cleanTimeout,
		exit:         make(chan struct{}),
		cleanCh:      make(chan *CleanupEvent, 1),
		batch: CleanBatch{
			batch: blockchain.db.NewBatch(),
		},
		filter:     bloom.NewWithEstimates(maxKeyCount, 0.01),
		blockchain: blockchain,
	}

	if c.cleanTimeout < minCleanTimeout {
		c.cleanTimeout = minCleanTimeout
	}

	buf, err := c.blockchain.db.Get(lastNumberKey)
	if err == nil && len(buf) > 0 {
		lastNumber := common.BytesToUint64(buf)
		atomic.StoreUint64(&c.lastNumber, lastNumber)
	}

	c.scope.Track(c.cleanFeed.Subscribe(c.cleanCh))
	go c.loop()
	return c
}

func (c *Cleaner) Stop() {
	c.scope.Close()
	close(c.exit)
}

func (c *Cleaner) Cleanup(blockNumber uint64) {
	if atomic.LoadInt32(&c.cleaning) == idleState {
		c.cleanFeed.Send(&CleanupEvent{blockNumber})
	}
}

func (c *Cleaner) NeedCleanup() bool {
	lastNumber := atomic.LoadUint64(&c.lastNumber)
	return c.blockchain.CurrentBlock().NumberU64()-lastNumber >= c.interval
}

func (c *Cleaner) OnNode(key []byte) {
	c.filterAdd(key[len(trie.MerklePrefix):])
}

func (c *Cleaner) OnPreImage(key []byte) {
	c.filterAdd(key[len(trie.SecureKeyPrefix):])
}

func (c *Cleaner) OnWrite() {
	if atomic.LoadInt32(&c.cleaning) == idleState {
		return
	}

	c.batch.WriteAndRest()
}

func (c *Cleaner) loop() {
	for {
		select {
		case ev := <-c.cleanCh:
			if atomic.LoadInt32(&c.cleaning) == idleState {
				go c.cleanup(ev.Number)
			}
		case <-c.exit:
			return
		}
	}
}

func (c *Cleaner) cleanup(blockNumber uint64) {
	if atomic.LoadInt32(&c.cleaning) == cleaningState {
		return
	}
	atomic.StoreInt32(&c.cleaning, cleaningState)
	defer atomic.StoreInt32(&c.cleaning, idleState)
	defer c.filterReset()

	db, ok := c.blockchain.db.(*ethdb.LDBDatabase)
	if !ok {
		log.Warn("The database not a leveldb, discard cleanup operation")
		return
	}

	lastNumber := atomic.LoadUint64(&c.lastNumber)
	if blockNumber-lastNumber <= cleanDistance {
		return
	}
	cleanPoint := c.blockchain.GetBlockByNumber(blockNumber - cleanDistance)
	if cleanPoint == nil {
		return
	}

	var (
		receipts = 0
		keys     = 0
	)

	t := time.Now()
	log.Debug("Start cleanup database", "interval", c.interval, "cleanTimeout", c.cleanTimeout, "lastNumber", atomic.LoadUint64(&c.lastNumber), "blockNumber", blockNumber, "cleanPoint", cleanPoint.NumberU64(), "root", cleanPoint.Root())
	defer func() {
		log.Debug("Finish cleanup database", "lastNumber", atomic.LoadUint64(&c.lastNumber), "cleanPoint", cleanPoint.NumberU64(), "receipts", receipts, "keys", keys, "elapsed", time.Since(t))
	}()

	number := lastNumber
	for number = c.lastNumber; number <= cleanPoint.NumberU64(); number++ {
		headerByNumber := c.blockchain.GetHeaderByNumber(number)
		if headerByNumber == nil {
			log.Error("Found bad hash", "number", number)
			continue
		}

		rawdb.DeleteReceipts(db, headerByNumber.Hash(), headerByNumber.Number.Uint64())
		receipts++

		if time.Since(t) >= c.cleanTimeout {
			atomic.StoreUint64(&c.lastNumber, number)
			db.Put(lastNumberKey, common.Uint64ToBytes(number))
			return
		}
	}
	atomic.StoreUint64(&c.lastNumber, number-1)
	db.Put(lastNumberKey, common.Uint64ToBytes(number-1))

	filterFn := func(key []byte) {
		c.filterAdd(key)
	}
	if err := ScanStateTrie(c.blockchain.CurrentBlock().Root(), c.blockchain.stateCache.TrieDB(), filterFn, filterFn, filterFn); err != nil {
		log.Error("Failed to scan stat trie", "")
		return
	}
	log.Debug("Bloom filter", "count", c.filter.K())

	iterateOver := func(iter ethdb.Iterator, prefix []byte) (bool, error) {
		for iter.Next() {
			if !c.filterTest(iter.Key()[len(prefix):]) {
				c.batch.Delete(iter.Key())
				keys++
			}

			if c.batch.ValueSize() > ethdb.IdealBatchSize {
				if err := c.batch.WriteAndRest(); err != nil {
					log.Error("Batch write fail", "err", err)
					return false, err
				}
			}

			if time.Since(t) >= c.cleanTimeout {
				if c.batch.ValueSize() > 0 {
					c.batch.WriteAndRest()
				}
				log.Debug("Cleanup database timeout", "lastNumber", atomic.LoadUint64(&c.lastNumber), "elapsed", time.Since(t))
				return true, nil
			}
		}
		return false, nil
	}

	iter := db.NewIteratorWithPrefix(trie.MerklePrefix)
	timeout, err := iterateOver(iter, trie.MerklePrefix)
	if timeout || err != nil {
		return
	}

	iter = db.NewIteratorWithPrefix(trie.SecureKeyPrefix)
	timeout, err = iterateOver(iter, trie.SecureKeyPrefix)
	if timeout || err != nil {
		return
	}
	if c.batch.ValueSize() > 0 {
		c.batch.WriteAndRest()
	}
}

func (c *Cleaner) filterAdd(key []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.filter.Add(key)
}

func (c *Cleaner) filterTest(key []byte) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.filter.Test(key)
}

func (c *Cleaner) filterReset() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.filter.ClearAll()
}

func ScanStateTrie(root common.Hash, db *trie.Database, onNode keyCallback, onValue keyCallback, onPreImage keyCallback) error {
	var stateTrie *trie.SecureTrie
	var err error
	if stateTrie, err = trie.NewSecure(root, db, 0); err != nil {
		return fmt.Errorf("new secure trie failed :%v", err)
	}
	iter := stateTrie.NodeIterator(nil)
	for iter.Next(true) {
		if iter.Hash() != (common.Hash{}) {
			onNode(iter.Hash().Bytes())
		}
		if iter.Leaf() {
			onPreImage(iter.LeafKey())

			var account state.Account
			if err := rlp.DecodeBytes(iter.LeafBlob(), &account); err != nil {
				return fmt.Errorf("parse account failed:%v", err)
			}

			if account.Root != emptyState {
				if err := ScanAccountTrie(account.Root, db, onNode, onValue, onPreImage); err != nil {
					return fmt.Errorf("scan account trie failed :%v", err)
				}
			}
		}
	}
	if iter.Error() != nil {
		return iter.Error()
	}
	return nil
}

func ScanAccountTrie(root common.Hash, db *trie.Database, onNode keyCallback, onValue keyCallback, onPreImage keyCallback) error {
	var accountTrie *trie.SecureTrie
	var err error
	if accountTrie, err = trie.NewSecure(root, db, 0); err != nil {
		return err
	}
	iter := accountTrie.NodeIterator(nil)
	for iter.Next(true) {
		if iter.Hash() != (common.Hash{}) {
			onNode(iter.Hash().Bytes())
		}
		if iter.Leaf() {
			onPreImage(iter.LeafKey())
			var valueKey common.Hash
			var buf []byte
			if err := rlp.DecodeBytes(iter.LeafBlob(), &buf); err != nil {
				return fmt.Errorf("decode account leaf %s failed : %v", hexutil.Encode(iter.LeafBlob()), err)
			}
			valueKey.SetBytes(buf)
			onValue(valueKey.Bytes())
		}
	}
	if iter.Error() != nil {
		return iter.Error()
	}
	return nil
}
