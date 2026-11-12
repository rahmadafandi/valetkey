package proxy

import (
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestCheckDrift(t *testing.T) {
	f := newFake(t, fakeOpts{Tools: []fakeTool{{Name: "echo", Description: "Echo back."}, {Name: "extra"}}})
	p := newProxy(t, f)
	user, err := p.Store.UpsertUser(ctx, "rahmad@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, err := p.Store.CreateUpstream(ctx, store.Upstream{UserID: user.ID, Name: "github", URL: f.URL, Auth: "none"})
	if err != nil {
		t.Fatal(err)
	}
	changedAt := func() *time.Time {
		t.Helper()
		got, err := p.Store.GetUpstream(ctx, user.ID, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.ToolsChangedAt
	}
	approve := func() {
		t.Helper()
		cs, _, err := p.Fetch(ctx, u, tools.Creds{})
		if err != nil {
			t.Fatal(err)
		}
		// Approve echo only: a tool the user left out must never count as drift.
		for _, c := range cs {
			if c.Name == "echo" {
				if err := p.Store.ApproveTools(ctx, user.ID, u.ID, Snapshot([]Candidate{c})); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	const force = -time.Hour // every upstream is due

	p.CheckDrift(ctx, force) // nothing approved yet, so nothing to compare
	approve()
	p.CheckDrift(ctx, force)
	if changedAt() != nil {
		t.Fatal("unchanged tools were flagged")
	}

	f.setTools([]fakeTool{{Name: "echo", Description: "Echo, louder."}, {Name: "extra"}})
	p.CheckDrift(ctx, time.Hour) // checked a moment ago: not due
	if changedAt() != nil {
		t.Fatal("checked again before it was due")
	}
	p.CheckDrift(ctx, force)
	if changedAt() == nil {
		t.Fatal("a changed description was not flagged")
	}

	approve()
	if changedAt() != nil {
		t.Fatal("approving the new list kept the flag")
	}
	f.setTools([]fakeTool{{Name: "extra"}})
	p.CheckDrift(ctx, force)
	if changedAt() == nil {
		t.Fatal("a removed tool was not flagged")
	}
}
