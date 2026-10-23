// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Package nodes resolves endpoint addresses to node-label snapshots.
package nodes

import (
	"net/netip"
	"slices"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
)

// StateDBResolver resolves endpoint addresses to node-label snapshots locklessly
// using StateDB's NodeAddressIndex.
type StateDBResolver struct {
	db          *statedb.DB
	nodes       statedb.Table[*node.Node]
	ipcache     *ipcache.IPCache
	clusterInfo cmtypes.ClusterInfo
}

var _ getters.NodeLabelsGetter = (*StateDBResolver)(nil)

// NewStateDBResolver constructs a resolver querying StateDB's node table.
func NewStateDBResolver(
	db *statedb.DB,
	nodes statedb.Table[*node.Node],
	ipc *ipcache.IPCache,
	clusterInfo cmtypes.ClusterInfo,
) *StateDBResolver {
	return &StateDBResolver{
		db:          db,
		nodes:       nodes,
		ipcache:     ipc,
		clusterInfo: clusterInfo,
	}
}

// GetNodeLabels resolves node labels locklessly using StateDB.
func (r *StateDBResolver) GetNodeLabels(ip netip.Addr, hint getters.NodeClusterHint) []string {
	if !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()

	ipcacheScope, expectedCluster, ok := r.resolveScope(hint)
	if !ok {
		return nil
	}

	if r.ipcache != nil {
		hostIP, found := r.ipcache.GetHostIP(cmtypes.AddrClusterFrom(ip, ipcacheScope))
		if found {
			return r.labelsForAddress(hostIP, expectedCluster)
		}
	}

	// Direct-node fallback is permitted only after an exact scoped IPCache miss
	// and retains the already authenticated expected ClusterID.
	return r.labelsForAddress(ip, expectedCluster)
}

func (r *StateDBResolver) resolveScope(hint getters.NodeClusterHint) (ipcacheScope, expectedCluster uint32, ok bool) {
	if hint.LocalEndpoint {
		if !hint.IdentityKnown || hint.Identity == identity.IdentityUnknown || isLocalOnlyReserved(hint.Identity) {
			return 0, r.clusterInfo.ID, true
		}
		clusterID, allocated := allocatedClusterID(hint.Identity, r.clusterInfo)
		if allocated && clusterID == r.clusterInfo.ID {
			return 0, r.clusterInfo.ID, true
		}
		return 0, 0, false
	}

	if !hint.IdentityKnown {
		return 0, 0, false
	}
	if hint.Identity == identity.ReservedIdentityHost {
		return 0, r.clusterInfo.ID, true
	}

	clusterID, allocated := allocatedClusterID(hint.Identity, r.clusterInfo)
	if !allocated {
		return 0, 0, false
	}
	if clusterID == r.clusterInfo.ID {
		return 0, r.clusterInfo.ID, true
	}
	return clusterID, clusterID, true
}

func isLocalOnlyReserved(id identity.NumericIdentity) bool {
	switch id {
	case identity.ReservedIdentityHost, identity.ReservedIdentityHealth, identity.ReservedIdentityIngress:
		return true
	default:
		return false
	}
}

func allocatedClusterID(id identity.NumericIdentity, cinfo cmtypes.ClusterInfo) (uint32, bool) {
	if id.HasLocalScope() || id.HasRemoteNodeScope() || id.Scope() != identity.IdentityScopeGlobal ||
		id.IsReservedIdentity() || identity.IsUserReservedIdentity(id) {
		return 0, false
	}

	clusterID := id.ClusterID(cinfo)
	if id.Uint32() < cinfo.MinimalAllocationIdentityFor(clusterID) || id.Uint32() > cinfo.MaximumAllocationIdentityFor(clusterID) {
		return 0, false
	}
	return clusterID, true
}

func (r *StateDBResolver) labelsForAddress(address netip.Addr, expectedCluster uint32) []string {
	if !address.IsValid() || r.nodes == nil || r.db == nil {
		return nil
	}
	address = address.Unmap()

	txn := r.db.ReadTxn()

	// Query StateDB NodeByAddress index with cluster scope
	addrCluster := cmtypes.AddrClusterFrom(address, expectedCluster)
	n, _, found := r.nodes.Get(txn, node.NodeByAddress(addrCluster))
	if !found {
		// Fall back to globally scoped underlay address (clusterID 0)
		addrCluster = cmtypes.AddrClusterFrom(address, 0)
		n, _, found = r.nodes.Get(txn, node.NodeByAddress(addrCluster))
	}
	if !found || n == nil || len(n.Labels) == 0 {
		return nil
	}

	return sortedLabels(n.Labels)
}

func sortedLabels(source map[string]string) []string {
	if len(source) == 0 {
		return nil
	}
	labels := make([]string, 0, len(source))
	for key, value := range source {
		labels = append(labels, key+"="+value)
	}
	slices.Sort(labels)
	return labels
}
