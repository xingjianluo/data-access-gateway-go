package policy

import (
	"context"
	"testing"
)

func TestSnapshotIsolationAcrossHotUpdate(t *testing.T) {
	p1 := &Policy{Version: "v1", Rules: []Rule{
		{ID: "r1", Effect: EffectAllow, Resource: "doc"},
	}}
	st := NewStore(p1)
	ctx := context.Background()

	snap, _ := st.Current(ctx)
	if snap.Version != "v1" {
		t.Fatalf("seed version: %s", snap.Version)
	}

	p2 := &Policy{Version: "v2", Rules: []Rule{
		{ID: "r2", Effect: EffectDeny, Resource: "doc"},
	}}
	if err := st.Update(ctx, p2); err != nil {
		t.Fatal(err)
	}

	// The captured request snapshot is immutable despite the hot update.
	if snap.Version != "v1" || len(snap.Rules) != 1 || snap.Rules[0].ID != "r1" {
		t.Fatalf("in-flight snapshot changed under the request: %+v", snap)
	}
	cur, _ := st.Current(ctx)
	if cur.Version != "v2" {
		t.Fatalf("new requests must see v2, got %s", cur.Version)
	}
	old, _ := st.Get(ctx, "v1")
	if old == nil || old.Version != "v1" {
		t.Fatal("historical version must remain retrievable for audit")
	}
}

func TestUpdateRejectsInvalidAndDuplicate(t *testing.T) {
	st := NewStore(nil)
	ctx := context.Background()
	if err := st.Update(ctx, nil); err != ErrPolicyInvalid {
		t.Fatalf("nil policy: %v", err)
	}
	p := &Policy{Version: "", Rules: []Rule{{ID: "r1", Effect: EffectAllow, Resource: "doc"}}}
	if err := st.Update(ctx, p); err == nil {
		t.Fatal("empty version must be rejected")
	}
	p.Version = "v1"
	if err := st.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(ctx, &Policy{Version: "v1"}); err != ErrVersionExists {
		t.Fatalf("duplicate version: %v", err)
	}
}
