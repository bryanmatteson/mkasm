package ptx

import "testing"

func TestMatchSyncDocumentFamily(t *testing.T) {
	for _, opcode := range []string{"match.any.sync.b32", "match.any.sync.b64", "match.all.sync.b32", "match.all.sync.b64"} {
		docs := Default().Lookup(opcode)
		if len(docs) != 1 || docs[0].ID != "parallel-synchronization-and-communication-instructions-match-sync" || docs[0].MinTarget != 70 {
			t.Fatalf("%s: %+v", opcode, docs)
		}
	}
	for _, opcode := range []string{"match.none.sync.b32", "match.any.syncx.b32", "match.anything.sync.b32"} {
		if docs := Default().Lookup(opcode); len(docs) != 0 {
			t.Fatalf("invalid family %s: %+v", opcode, docs)
		}
	}
}

func TestTCGenScopeDocumentFamilies(t *testing.T) {
	for _, op := range []string{"tcgen05.fence::before_thread_sync", "tcgen05.fence::after_thread_sync", "tcgen05.wait::ld.sync.aligned", "tcgen05.wait::st.sync.aligned"} {
		docs := Default().Lookup(op)
		if len(docs) != 1 || docs[0].MinVersion != 86 || docs[0].MinTarget != 100 {
			t.Fatalf("%s: %+v", op, docs)
		}
		m, err := Default().Assemble(".version 8.6\n.target sm_100a\n.address_size 64\n.entry k(){"+op+";ret;}", Profile{})
		if err != nil || len(m.Instructions) != 2 {
			t.Fatalf("%s: %v", op, err)
		}
	}
	for _, op := range []string{"tcgen05.waitx::ld.sync.aligned", "tcgen05.fence:before_thread_sync", "tcgen05x.fence::after_thread_sync"} {
		if docs := Default().Lookup(op); len(docs) != 0 {
			t.Fatalf("invalid family %s: %+v", op, docs)
		}
	}
}
