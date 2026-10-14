package store

import (
	"errors"
	"fmt"
	"testing"
)

func mkUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	u, err := s.UpsertUser(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mkUpstream(t *testing.T, s *Store, userID, name string) Upstream {
	t.Helper()
	u, err := s.CreateUpstream(ctx, Upstream{UserID: userID, Name: name, URL: "https://" + name + ".example.com/mcp", Auth: "none"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func toolNames(ts []UpstreamTool) []string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Name)
	}
	return n
}

func TestUpstreamIsolationAndLimits(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	ua := mkUpstream(t, s, a.ID, "github")
	mkUpstream(t, s, a.ID, "alpha")
	ub := mkUpstream(t, s, b.ID, "github")
	if ua.ID == "" || ua.CreatedAt.IsZero() || ua.ID == ub.ID {
		t.Fatalf("ua=%+v", ua)
	}
	la, _ := s.ListUpstreams(ctx, a.ID)
	lb, _ := s.ListUpstreams(ctx, b.ID)
	if len(la) != 2 || la[0].Name != "alpha" || len(lb) != 1 || lb[0].ID != ub.ID {
		t.Fatalf("la=%+v lb=%+v", la, lb)
	}
	if _, err := s.GetUpstream(ctx, b.ID, ua.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if got, err := s.GetUpstream(ctx, a.ID, ua.ID); err != nil || got.ID != ua.ID {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := s.CreateUpstream(ctx, Upstream{UserID: a.ID, Name: "github", URL: "https://x", Auth: "none"}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("got %v", err)
	}
	for i := 2; i < MaxUpstreams; i++ {
		mkUpstream(t, s, a.ID, fmt.Sprintf("s%d", i))
	}
	if _, err := s.CreateUpstream(ctx, Upstream{UserID: a.ID, Name: "over", URL: "https://x", Auth: "none"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v", err)
	}
}

func TestApproveTools(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	ua := mkUpstream(t, s, a.ID, "github")
	if err := s.ApproveTools(ctx, a.ID, ua.ID, []UpstreamTool{
		{Name: "read", Description: "d", InputSchema: "{}"}, {Name: "write", InputSchema: "{}", Writes: true},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUpstream(ctx, a.ID, ua.ID)
	if got.ToolsApprovedAt == nil {
		t.Fatal("ToolsApprovedAt not set")
	}
	ts, _ := s.ApprovedTools(ctx, a.ID, ua.ID)
	if len(ts) != 2 || ts[0].Name != "read" || !ts[1].Writes || ts[0].ApprovedAt.IsZero() {
		t.Fatalf("ts=%+v", ts)
	}
	if err := s.ApproveTools(ctx, a.ID, ua.ID, []UpstreamTool{{Name: "other", InputSchema: "{}"}}); err != nil {
		t.Fatal(err)
	}
	ts, _ = s.ApprovedTools(ctx, a.ID, ua.ID)
	if len(ts) != 1 || ts[0].Name != "other" {
		t.Fatalf("ts=%+v", ts)
	}
	if err := s.ApproveTools(ctx, b.ID, ua.ID, []UpstreamTool{{Name: "evil", InputSchema: "{}"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	ts, _ = s.ApprovedTools(ctx, a.ID, ua.ID)
	if len(ts) != 1 || ts[0].Name != "other" {
		t.Fatalf("changed: %+v", ts)
	}
	if ts, err := s.ApprovedTools(ctx, b.ID, ua.ID); err != nil || len(ts) != 0 {
		t.Fatalf("B sees %+v %v", ts, err)
	}
}

func TestUserTools(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	ua, ua2, ub := mkUpstream(t, s, a.ID, "github"), mkUpstream(t, s, a.ID, "alpha"), mkUpstream(t, s, b.ID, "github")
	s.ApproveTools(ctx, a.ID, ua.ID, []UpstreamTool{{Name: "z", InputSchema: "{}"}, {Name: "a", InputSchema: "{}"}})
	s.ApproveTools(ctx, a.ID, ua2.ID, []UpstreamTool{{Name: "m", InputSchema: "{}"}})
	s.ApproveTools(ctx, b.ID, ub.ID, []UpstreamTool{{Name: "secret", InputSchema: "{}"}})
	got, err := s.UserTools(ctx, a.ID)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %+v %v", got, err)
	}
	want := [][2]string{{"alpha", "m"}, {"github", "a"}, {"github", "z"}}
	for i, w := range want {
		if got[i].Upstream.Name != w[0] || got[i].Tool.Name != w[1] || got[i].Upstream.UserID != a.ID {
			t.Fatalf("row %d: %+v", i, got[i])
		}
	}
	gb, _ := s.UserTools(ctx, b.ID)
	if len(gb) != 1 || gb[0].Tool.Name != "secret" {
		t.Fatalf("gb=%+v", gb)
	}
}

func TestRemoveTools(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	ua := mkUpstream(t, s, a.ID, "github")
	s.ApproveTools(ctx, a.ID, ua.ID, []UpstreamTool{{Name: "a", InputSchema: "{}"}, {Name: "b", InputSchema: "{}"}, {Name: "c", InputSchema: "{}"}})
	if err := s.RemoveTools(ctx, b.ID, ua.ID, []string{"a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := s.RemoveTools(ctx, a.ID, ua.ID, []string{"a", "c"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := s.ApprovedTools(ctx, a.ID, ua.ID)
	if n := toolNames(ts); len(n) != 1 || n[0] != "b" {
		t.Fatalf("left %v", n)
	}
}

func TestDeleteUpstream(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	u1, u2, ub := mkUpstream(t, s, a.ID, "github"), mkUpstream(t, s, a.ID, "other"), mkUpstream(t, s, b.ID, "github")
	for _, x := range []struct{ u, id string }{{a.ID, u1.ID}, {a.ID, u2.ID}, {b.ID, ub.ID}} {
		s.ApproveTools(ctx, x.u, x.id, []UpstreamTool{{Name: "t", InputSchema: "{}"}})
		for _, sys := range []string{"upstream:" + x.id, "upstream:" + x.id + "/pending"} {
			if err := s.PutCredential(ctx, x.u, sys, []byte("sealed")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.DeleteUpstream(ctx, a.ID, ub.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.GetCredential(ctx, b.ID, "upstream:"+ub.ID); err != nil {
		t.Fatalf("B credential touched: %v", err)
	}
	if err := s.DeleteUpstream(ctx, a.ID, u1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUpstream(ctx, a.ID, u1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	for _, sys := range []string{"upstream:" + u1.ID, "upstream:" + u1.ID + "/pending"} {
		if _, err := s.GetCredential(ctx, a.ID, sys); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s left: %v", sys, err)
		}
	}
	if ts, _ := s.UserTools(ctx, a.ID); len(ts) != 1 || ts[0].Upstream.ID != u2.ID {
		t.Fatalf("a tools: %+v", ts)
	}
	if _, err := s.GetCredential(ctx, a.ID, "upstream:"+u2.ID+"/pending"); err != nil {
		t.Fatal(err)
	}
	if ts, _ := s.UserTools(ctx, b.ID); len(ts) != 1 {
		t.Fatalf("b tools: %+v", ts)
	}
	var n int
	if err := s.db.NewSelect().Table("upstream_tools").ColumnExpr("count(*)").Where("upstream_id = ?", u1.ID).Scan(ctx, &n); err != nil || n != 0 {
		t.Fatalf("tools left %d %v", n, err)
	}
}

func TestDeleteUserCascadesUpstreams(t *testing.T) {
	s := OpenTest(t)
	a, b := mkUser(t, s, "a@example.com"), mkUser(t, s, "b@example.com")
	ua, ub := mkUpstream(t, s, a.ID, "github"), mkUpstream(t, s, b.ID, "github")
	s.ApproveTools(ctx, a.ID, ua.ID, []UpstreamTool{{Name: "t", InputSchema: "{}"}})
	s.ApproveTools(ctx, b.ID, ub.ID, []UpstreamTool{{Name: "t", InputSchema: "{}"}})
	if _, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", a.ID); err != nil {
		t.Fatal(err)
	}
	var up, tl int
	s.db.NewSelect().Table("upstreams").ColumnExpr("count(*)").Where("user_id = ?", a.ID).Scan(ctx, &up)
	s.db.NewSelect().Table("upstream_tools").ColumnExpr("count(*)").Where("upstream_id = ?", ua.ID).Scan(ctx, &tl)
	if up != 0 || tl != 0 {
		t.Fatalf("up=%d tools=%d", up, tl)
	}
	if ts, _ := s.UserTools(ctx, b.ID); len(ts) != 1 {
		t.Fatalf("b lost data: %+v", ts)
	}
}
