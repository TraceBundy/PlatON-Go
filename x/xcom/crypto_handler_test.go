package xcom

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/PlatONnetwork/PlatON-Go/log"

	"github.com/PlatONnetwork/PlatON-Go/common"

	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"
)

var (
	//priKey = crypto.HexMustToECDSA("8e1477549bea04b97ea15911e2e9b3041b7a9921f80bd6ddbe4c2b080473de22")
	priKey = crypto.HexMustToECDSA("8c56e4a0d8bb1f82b94231d535c499fdcbf6e06221acf669d5a964f5bb974903")

	//nodeID = discover.MustHexID("3e7864716b671c4de0dc2d7fd86215e0dcb8419e66430a770294eb2f37b714a07b6a3493055bb2d733dee9bfcc995e1c8e7885f338a69bf6c28930f3cf341819")
	nodeID = discover.MustHexID("3a06953a2d5d45b29167bef58208f1287225bdd2591260af29ae1300aeed362e9b548369dfc1659abbef403c9b3b07a8a194040e966acd6e5b6d55aa2df7c1d8")
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

func Test_Decode(t *testing.T) {
	initChandlerHandler()
	log.Root().SetHandler(log.CallerFileHandler(log.LvlFilterHandler(log.Lvl(6), log.StreamHandler(os.Stderr, log.TerminalFormat(true)))))

	versionSign, err := hex.DecodeString("e9626170e0c02d86c329193af7d2138813596f7bfdad16608015f92873a40b70641130f04f76cb506de059462472f9f0041bdb37e9be18303e2bbab6b6e61d0401")
	if err != nil {
		log.Error("Decode hex String", "err", err)
		return
	}
	if !chandler.IsSignedByNodeID(uint32(1793), versionSign, nodeID) {
		t.Error("verify sign error")
	} else {
		t.Error("verify sign OK")
	}

}
