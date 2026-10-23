// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nodes

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

const (
	localCluster    = "cluster-local"
	localClusterID  = uint32(1)
	remoteCluster   = "cluster-remote"
	remoteClusterID = uint32(2)
)

var (
	testLocalClusterInfo = cmtypes.ClusterInfo{
		ID:                   localClusterID,
		Name:                 localCluster,
		MaxConnectedClusters: 255,
	}
	testRemoteClusterInfo = cmtypes.ClusterInfo{
		ID:                   remoteClusterID,
		Name:                 remoteCluster,
		MaxConnectedClusters: 255,
	}
)

func setupTestResolver(t testing.TB) (*StateDBResolver, statedb.RWTable[*node.Node], *statedb.DB, *ipcache.IPCache) {
	t.Helper()
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	require.NoError(t, err)

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Logger: hivetest.Logger(t),
	})
	r := NewStateDBResolver(db, nodeTable, ipc, testLocalClusterInfo)
	return r, nodeTable, db, ipc
}

func insertNode(t testing.TB, db *statedb.DB, nodeTable statedb.RWTable[*node.Node], name string, clusterID uint32, labels map[string]string, ipStrs ...string) {
	t.Helper()
	addresses := make([]nodeTypes.Address, 0, len(ipStrs))
	for _, ipStr := range ipStrs {
		addresses = append(addresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr(ipStr)),
		})
	}

	n := &node.Node{
		Node: nodeTypes.Node{
			Name:        name,
			ClusterID:   clusterID,
			Labels:      labels,
			IPAddresses: addresses,
		},
	}

	txn := db.WriteTxn(nodeTable)
	_, _, err := nodeTable.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
}

func TestStateDBResolver_DirectNodeHit(t *testing.T) {
	r, nodeTable, db, _ := setupTestResolver(t)

	insertNode(t, db, nodeTable, "node-1", localClusterID, map[string]string{
		"topology.kubernetes.io/zone": "zone-a",
		"kubernetes.io/hostname":      "node-1",
	}, "192.0.2.10")

	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		IdentityKnown: true,
	}

	labels := r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), hint)
	require.Equal(t, []string{
		"kubernetes.io/hostname=node-1",
		"topology.kubernetes.io/zone=zone-a",
	}, labels)
}

func TestStateDBResolver_IPCacheHostHit(t *testing.T) {
	r, nodeTable, db, ipc := setupTestResolver(t)

	insertNode(t, db, nodeTable, "node-1", localClusterID, map[string]string{
		"kubernetes.io/hostname": "node-1",
	}, "192.0.2.10")

	// Map Pod IP 10.0.0.1 to Host IP 192.0.2.10 in IPCache
	_, err := ipc.Upsert("10.0.0.1", net.ParseIP("192.0.2.10"), 0, nil, ipcache.Identity{
		ID:     identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		IdentityKnown: true,
	}

	labels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), hint)
	require.Equal(t, []string{"kubernetes.io/hostname=node-1"}, labels)
}

func TestStateDBResolver_RemoteClusterMeshHit(t *testing.T) {
	r, nodeTable, db, ipc := setupTestResolver(t)

	insertNode(t, db, nodeTable, "remote-node-1", remoteClusterID, map[string]string{
		"kubernetes.io/hostname": "remote-node-1",
	}, "192.0.2.20")

	addrCluster := cmtypes.MustParseAddrCluster("10.0.0.20@2")
	_, err := ipc.Upsert(addrCluster.String(), net.ParseIP("192.0.2.20"), 0, nil, ipcache.Identity{
		ID:     identity.NumericIdentity(testRemoteClusterInfo.MinimalAllocationIdentityFor(remoteClusterID)),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testRemoteClusterInfo.MinimalAllocationIdentityFor(remoteClusterID)),
		IdentityKnown: true,
	}

	labels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.20"), hint)
	require.Equal(t, []string{"kubernetes.io/hostname=remote-node-1"}, labels)
}

func TestStateDBResolver_UnknownProvenanceMiss(t *testing.T) {
	r, nodeTable, db, ipc := setupTestResolver(t)

	insertNode(t, db, nodeTable, "node-1", localClusterID, map[string]string{
		"kubernetes.io/hostname": "node-1",
	}, "192.0.2.10")

	_, err := ipc.Upsert("10.0.0.1", net.ParseIP("192.0.2.10"), 0, nil, ipcache.Identity{
		ID:     identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	// Unknown identity provenance -> returns nil
	hint := getters.NodeClusterHint{
		Identity:      identity.IdentityUnknown,
		IdentityKnown: false,
	}

	labels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), hint)
	require.Nil(t, labels)
}

func TestStateDBResolver_ConcurrentLookups(t *testing.T) {
	r, nodeTable, db, ipc := setupTestResolver(t)

	insertNode(t, db, nodeTable, "node-1", localClusterID, map[string]string{
		"kubernetes.io/hostname": "node-1",
	}, "192.0.2.10")

	_, err := ipc.Upsert("10.0.0.1", net.ParseIP("192.0.2.10"), 0, nil, ipcache.Identity{
		ID:     identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		Source: source.KVStore,
	})
	require.NoError(t, err)

	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		IdentityKnown: true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				labels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), hint)
				require.Equal(t, []string{"kubernetes.io/hostname=node-1"}, labels)
			}
		}()
	}
	wg.Wait()
}
