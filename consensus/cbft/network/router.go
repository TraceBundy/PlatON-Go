// Package cbft implements  a concrete consensus engines.
package network

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"sync"

	"github.com/PlatONnetwork/PlatON-Go/p2p/discover"

	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/protocols"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/types"
	"github.com/PlatONnetwork/PlatON-Go/consensus/cbft/utils"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/PlatONnetwork/PlatON-Go/p2p"
)

// The fanout value of the gossip protocol, used to indicate
// the number of nodes selected per broadcast.
const DEFAULT_FAN_OUT = 5

type unregisterFunc func(id string) error                 // Unregister peer from peerSet.
type getByIdFunc func(id string) (*peer, error)           // Get peer based on ID.
type consensusNodesFunc func() ([]discover.NodeID, error) // Get a list of consensus nodes.
type peersFunc func() ([]*peer, error)                    // Get a list of all neighbor nodes.

// Router implements the message protocol of gossip.
//
// 1.Responsible for picking receiving nodes based on message type.
// 2.Generate a random node list based on fan-out.
// 3.Duplicate verification of messages.
type router struct {
	filter func(*peer, common.Hash) bool // Used for filtering node
	lock   sync.RWMutex

	// Customized functions belonging to the router.
	unregister     unregisterFunc     // Used for deregistration.
	get            getByIdFunc        // Used to get peer by ID.
	consensusNodes consensusNodesFunc // Used to get a list of consensus nodes.
	peers          peersFunc          // Used to get all the nodes.
}

// NewRouter creates a new router. It is mainly used for message forwarding
func NewRouter(unregister unregisterFunc, get getByIdFunc, consensusNodes consensusNodesFunc, peers peersFunc) *router {
	r := &router{
		filter: func(p *peer, condition common.Hash) bool {
			return p.ContainsMessageHash(condition)
		},
	}
	r.initFunc(unregister, get, consensusNodes, peers)
	return r
}

// Init handler function.
func (r *router) initFunc(unregister unregisterFunc, get getByIdFunc, consensusNodes consensusNodesFunc, peers peersFunc) error {
	r.unregister, r.get, r.consensusNodes, r.peers = unregister, get, consensusNodes, peers
	return nil
}

// A is responsible for forwarding the message. It selects different
// target nodes based on the message type and forwarding mode.
func (r *router) Gossip(m *types.MsgPackage) {
	msgType := protocols.MessageType(m.Message())
	msgHash := m.Message().MsgHash()

	// Secondary forwarding verification.
	// If the message of type (PrepareBlockHashMsg) is not processed in the node list of all
	// neighbors of the current node, a message can be sent or not.
	if msgType == protocols.PrepareBlockHashMsg {
		if r.repeatedCheck(m.PeerID(), msgHash) {
			log.Warn("The message is repeated, not to forward again", "msgType", reflect.TypeOf(m.Message()), "msgHash", msgHash.TerminalString())
			return
		}
	}
	// pick target nodes by type.
	peers, err := r.filteredPeers(msgType, msgHash)
	if err != nil {
		log.Error("filteredPeers failed and stop to send", "msgType", msgType, "msgHash", msgHash, "err", err)
		return
	}
	// determine the number of target nodes based on different transmission modes.
	// PartMode: Select some of the nodes from all
	// recipients to reduce network consumption.
	switch m.Mode() {
	case types.PartMode:
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		peers = transfer
	}

	// Print the information of the target's node.
	pids := formatPeers(peers)
	log.Debug("Gossip message", "msgHash", msgHash.TerminalString(), "msgType", reflect.TypeOf(m.Message()), "targetPeer", pids)

	// Iteratively acquire nodes and send messages.
	for _, peer := range peers {
		if err := p2p.Send(peer.rw, msgType, m.Message()); err != nil {
			log.Error("Send message failed", "peer", peer.id, "err", err)
		} else {
			peer.MarkMessageHash(msgHash)
		}
	}
}

// Send message to a known peerId. Determine if the peerId has established
// a connection before sending.
func (h *router) SendMessage(m *types.MsgPackage) {
	if peer, err := h.get(m.PeerID()); err == nil {
		log.Debug("Send message", "targetPeer", m.PeerID(), "type", reflect.TypeOf(m.Message()),
			"msgHash", m.Message().MsgHash(), "BHash", m.Message().BHash())
		if err := p2p.Send(peer.rw, protocols.MessageType(m.Message()), m.Message()); err != nil {
			log.Error("Send Peer error")
			h.unregister(m.PeerID())
		}
	}
}

// filteredPeers selects the appropriate peers that satisfies the condition based on the message type.
//
// rules:
// 1.Some message types return all consensus nodes.
// 2.Some message types return random consensus nodes.
// The following types return all consensus nodes:
//   PrepareVoteMsg/PrepareBlockMsg/ViewChangeMsg/BlockQuorumCertMsg
// The following types return a consensus node with non-consensus:
//   PrepareBlockHashMsg
func (r *router) filteredPeers(msgType uint64, condition common.Hash) ([]*peer, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	// todo: Test the anchor point, please pay attention to let go.
	//return r.peers()
	switch msgType {
	case protocols.PrepareBlockMsg, protocols.PrepareVoteMsg,
		protocols.ViewChangeMsg, protocols.BlockQuorumCertMsg:
		return r.kMixingRandomNodes(condition)
	case protocols.PrepareBlockHashMsg, protocols.GetLatestStatusMsg, protocols.GetViewChangeMsg:
		return r.kConsensusRandomNodes(false, condition)
	}
	return nil, fmt.Errorf("does not match the type of the specified message")
}

// Randomly return a list of consensus nodes that exist in the PeerSet.
//
// 1.Get all consensus node IDs.
// 2.Get a list of neighbor nodes.
// 3.Take the intersection of the above.
// 4.If the random is true then get the number of random nodes and the fan-out is 5.
func (r *router) kConsensusRandomNodes(random bool, condition common.Hash) ([]*peer, error) {
	cNodes, err := r.consensusNodes()
	if err != nil {
		return nil, err
	}
	existsPeers, err := r.peers()
	if err != nil {
		return nil, err
	}
	log.Debug("kConsensusRandomNodes select node", "msgHash", condition, "cNodesLen", len(cNodes), "peerSetLen", len(existsPeers))

	// The maximum capacity will not exceed the capacity of existsPeers.
	// Slices of the specified capacity have certain performance advantages.
	consensusPeers := make([]*peer, 0, len(existsPeers))
	for _, peer := range existsPeers {
		for _, node := range cNodes {
			if peer.id == node.TerminalString() {
				consensusPeers = append(consensusPeers, peer)
				break
			}
		}
		if peer.ContainsMessageHash(condition) {
			continue
		}
	}
	if random {
		return kRandomNodes(DEFAULT_FAN_OUT, consensusPeers, condition, r.filter), nil
	}
	return consensusPeers, nil
}

// kMixingRandomNodes returns all consensus nodes and k randomly generated non-consensus nodes.
func (r *router) kMixingRandomNodes(condition common.Hash) ([]*peer, error) {
	// all consensus nodes + a number of k non-consensus nodes
	cNodes, err := r.consensusNodes()
	log.Debug("consensusNodes in kMixingRandomNodes", "cNodes", len(cNodes), "ids", FormatNodes(cNodes))
	if err != nil {
		return nil, err
	}
	existsPeers, err := r.peers()
	if err != nil {
		return nil, err
	}
	consensusPeers := make([]*peer, 0, len(existsPeers))
	// The length of non-consensus nodes is equal to the default fan-out value.
	nonconsensusPeers := make([]*peer, 0, DEFAULT_FAN_OUT)
	for _, peer := range existsPeers {
		isConsensus := false
		for _, node := range cNodes {
			if peer.id == node.TerminalString() {
				isConsensus = true
				break
			}
		}
		if peer.ContainsMessageHash(condition) {
			continue
		}
		if isConsensus {
			consensusPeers = append(consensusPeers, peer)
		} else {
			nonconsensusPeers = append(nonconsensusPeers, peer)
		}
	}
	// Obtain random nodes from non-consensus nodes.
	kNonconsensusNodes := kRandomNodes(DEFAULT_FAN_OUT, nonconsensusPeers, condition, r.filter)
	// Summary target peers and return.
	consensusPeers = append(consensusPeers, kNonconsensusNodes...)
	return consensusPeers, nil
}

// kRandomNodes is used to select up to k random nodes, excluding any nodes where
// the filter function returns true. It is possible that less than k nodes are returned.
func kRandomNodes(k int, peers []*peer, condition common.Hash, filterFn func(*peer, common.Hash) bool) []*peer {
	n := len(peers)
	kNodes := make([]*peer, 0, k)
OUTER:
	// Probe up to 3*n times, with large n this is not necessary
	// since k << n, but with small n we want search to be
	// exhaustive.
	for i := 0; i < 3*n && len(kNodes) < k; i++ {
		// Get random node
		idx := utils.RandomOffset(n)
		node := peers[idx]

		// Give the filter a shot at it.
		if filterFn != nil && filterFn(node, condition) {
			continue OUTER
		}

		// Check if we have this node already
		for j := 0; j < len(kNodes); j++ {
			if node == kNodes[j] {
				continue OUTER
			}
		}
		// Append the node
		kNodes = append(kNodes, node)
	}
	return kNodes
}

// Check if the specified message has been processed by the neighbor node.
func (r *router) repeatedCheck(peerId string, msgHash common.Hash) bool {
	peers, err := r.peers()
	if err != nil {
		return false
	}
	for _, peer := range peers {
		if peer.id == peerId {
			continue
		}
		// if true: indicates that the neighbor node has been processed.
		if peer.ContainsMessageHash(msgHash) {
			return true
		}
	}
	// if false: indicates that no neighbor nodes have been processed.
	return false
}

// formatPeers is used to print the information about peer
func formatPeers(peers []*peer) string {
	var bf bytes.Buffer
	for idx, peer := range peers {
		bf.WriteString(peer.id)
		if idx < len(peers)-1 {
			bf.WriteString(",")
		}
	}
	return bf.String()
}

// formatNodes is used to print the information about peerID.
func FormatNodes(ids []discover.NodeID) string {
	var bf bytes.Buffer
	for idx, id := range ids {
		bf.WriteString(id.TerminalString())
		if idx < len(ids)-1 {
			bf.WriteString(",")
		}
	}
	return bf.String()
}
