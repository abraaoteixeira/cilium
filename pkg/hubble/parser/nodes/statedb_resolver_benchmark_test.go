// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nodes

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
)

var benchmarkLabels []string

func benchmarkStateDBResolver(b *testing.B, withIPCache bool) *StateDBResolver {
	b.Helper()
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	if err != nil {
		b.Fatalf("NewNodeTable failed: %v", err)
	}

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Logger: hivetest.Logger(b),
	})
	r := NewStateDBResolver(db, nodeTable, ipc, testLocalClusterInfo)

	insertNode(b, db, nodeTable, "node-1", localClusterID, map[string]string{
		"kubernetes.io/hostname":        "node-1",
		"topology.kubernetes.io/region": "region-a",
		"topology.kubernetes.io/zone":   "zone-a",
	}, "192.0.2.10")

	if withIPCache {
		_, _ = ipc.Upsert("10.0.0.1", net.ParseIP("192.0.2.10"), 0, nil, ipcache.Identity{
			ID:     identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
			Source: source.KVStore,
		})
		_, _ = ipc.Upsert("10.0.0.2", net.ParseIP("192.0.2.10"), 0, nil, ipcache.Identity{
			ID:     identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
			Source: source.KVStore,
		})
	}
	return r
}

func BenchmarkStateDBResolver_CacheHitBothDirections(b *testing.B) {
	r := benchmarkStateDBResolver(b, true)
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		IdentityKnown: true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkLabels = r.GetNodeLabels(src, hint)
		benchmarkLabels = r.GetNodeLabels(dst, hint)
	}
}

func BenchmarkStateDBResolver_DirectNodeHit(b *testing.B) {
	r := benchmarkStateDBResolver(b, false)
	ip := netip.MustParseAddr("192.0.2.10")
	hint := getters.NodeClusterHint{
		Identity:      identity.NumericIdentity(testLocalClusterInfo.MinimalAllocationIdentityFor(localClusterID)),
		IdentityKnown: true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkLabels = r.GetNodeLabels(ip, hint)
	}
}

func BenchmarkStateDBResolver_UnknownProvenanceMiss(b *testing.B) {
	r := benchmarkStateDBResolver(b, true)
	ip := netip.MustParseAddr("10.0.0.1")
	hint := getters.NodeClusterHint{Identity: identity.IdentityUnknown, IdentityKnown: false}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkLabels = r.GetNodeLabels(ip, hint)
	}
}
