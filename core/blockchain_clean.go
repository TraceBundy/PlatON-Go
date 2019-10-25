package core

import (
	"fmt"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/rlp"
	"github.com/PlatONnetwork/PlatON-Go/trie"
)

var (
	emptyState   = crypto.Keccak256Hash(nil)
	securePreifx = []byte("secure-key-")
)

type keyCallback func([]byte)

func ScanStateTrie(root common.Hash, db *trie.Database, onNode keyCallback, onValue keyCallback, onPreImage keyCallback) error {
	var stateTrie *trie.SecureTrie
	var err error
	if stateTrie, err = trie.NewSecure(root, db, 0); err != nil {
		return err
	}
	iter := stateTrie.NodeIterator(nil)
	for iter.Next(true) {
		if iter.Hash() != (common.Hash{}) {
			onNode(iter.Hash().Bytes())
		}
		if iter.Leaf() {
			origKey := append(securePreifx, iter.LeafKey()...)
			onPreImage(origKey)

			var account state.Account
			if err := rlp.DecodeBytes(iter.LeafBlob(), &account); err != nil {
				return fmt.Errorf("parse account failed:%v", err)
			}

			if account.Root != emptyState {
				if err := ScanAccountTrie(account.Root, db, onNode, onValue, onPreImage); err != nil {
					return err
				}
			}
		}
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
			origKey := append(securePreifx, iter.LeafKey()...)
			onPreImage(origKey)
			var valueKey common.Hash
			var buf []byte
			if err := rlp.DecodeBytes(iter.LeafBlob(), &buf); err != nil {
				return err
			}
			valueKey.SetBytes(buf)
			onValue(valueKey.Bytes())
		}
	}
	return nil
}
