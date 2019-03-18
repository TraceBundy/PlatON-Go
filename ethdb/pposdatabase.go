package ethdb

import (
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

//type PPosDatabase struct {
//	db *leveldb.DB // LevelDB instance
//}



func NewPPosDatabase (file string) (*LDBDatabase, error)  {

	logger := log.New("database", file)

	logger.Info("Allocated cache and file handles")

	// Open the db and recover any potential corruptions
	db, err := leveldb.OpenFile(file, &opt.Options{
		OpenFilesCacheCapacity: -1,	// Use -1 for zero, this has same effect as specifying NoCacher to OpenFilesCacher.
		BlockCacheCapacity:     -1, // Use -1 for zero, this has same effect as specifying NoCacher to BlockCacher.
		DisableBlockCache:		true,
		//CompactionL0Trigger: 	0,
		DisableBufferPool:		true,
		DisableLargeBatchTransaction: true,
		Filter:                 filter.NewBloomFilter(10),
	})

	//db, err := leveldb.OpenFile(file,nil)

	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil)
	}
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
		return nil, err
	}
	return &LDBDatabase{
		fn:  file,
		db:  db,
		log: logger,
	}, nil
}


