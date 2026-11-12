package proxy

import (
	"context"
	"time"
)

// CheckDrift compares each upstream not checked since `every` ago with its
// approved snapshot and records whether an approved tool changed or went away.
// Tools the server added are not drift: the user may have left them out on
// purpose. An upstream that cannot be reached keeps its last answer.
func (p *Proxy) CheckDrift(ctx context.Context, every time.Duration) {
	us, err := p.Store.ClaimDriftChecks(ctx, time.Now().Add(-every))
	if err != nil {
		p.log().Warn("drift check: list upstreams", "err", err)
	}
	for _, u := range us {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := func() error {
			c, err := p.Login(cctx, u.UserID, u)
			if err != nil {
				return err
			}
			cands, _, err := p.Fetch(cctx, u, c)
			if err != nil {
				return err
			}
			approved, err := p.Store.ApprovedTools(cctx, u.UserID, u.ID)
			if err != nil {
				return err
			}
			d := Compare(approved, cands)
			return p.Store.SetToolsChanged(cctx, u.ID, len(d.Changed)+len(d.Removed) > 0)
		}()
		cancel()
		if err != nil {
			p.log().Info("drift check skipped", "upstream", u.ID, "err", err)
		}
	}
}
