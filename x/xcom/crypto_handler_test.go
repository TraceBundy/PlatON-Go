package xcom

import (
	"encoding/hex"
	"testing"

	"github.com/PlatONnetwork/PlatON-Go/common"

	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"
)

var (
	priKey = crypto.HexMustToECDSA("d30b490011d2a08053d46506ae533ff96f2cf6a37f73be740f52ad24243c4958")
	nodeID = discover.MustHexID("a20aef0b2c6baeaa34be2848e7dfc04c899b5985adf6fa0e98b38f754f2bb0c47974506a8de13f2a2ae97c08bcb12b438b3dcbf237b7be58f6d6d8beb36dd235")
)

func initChandlerHandler() {
	chandler = GetCryptoHandler()
	chandler.SetPrivateKey(priKey)
}

func TestCryptoHandler_IsSignedByNodeID(t *testing.T) {
	initChandlerHandler()
	version := uint32(1<<16 | 1<<8 | 0)
	sig := chandler.MustSign(version)

	versionSign := common.VersionSign{}
	versionSign.SetBytes(sig)

	t.Log("...", "version", version, "sig", hex.EncodeToString(sig))

	if !chandler.IsSignedByNodeID(version, versionSign.Bytes(), nodeID) {
		t.Fatal("verify sign error")
	}
}
