package notion

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (n *Notion) ScopeKey() string { return "notion" }

// ParseScope reads one or more page, database or data source IDs or links. A
// token reaches those and everything under them.
func (n *Notion) ParseScope(raw json.RawMessage) (any, error) {
	list, err := tools.StringOrList(raw)
	if err != nil {
		return nil, errors.New(`expected a page or database ID or link, or a list of them`)
	}
	ids := make([]string, 0, len(list))
	for _, s := range list {
		id, err := normID(s)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// CheckScope lets every call through: whether a page sits under an allowed one
// can only be answered by Notion, so each tool's Run asks, through within.
func (n *Notion) CheckScope(any, string, json.RawMessage) error { return nil }

// maxDepth bounds how far up the tree within walks looking for an allowed parent.
const maxDepth = 12

var (
	errTooDeep    = errors.New("too deep to check")
	errOverBudget = errors.New("too many lookups to check")
)

// walk carries what one tool call has learned about the tree.
type walk struct {
	seen   map[string]bool // answers so far, by normalized ID
	capped bool            // left counts down
	left   int             // API lookups left when capped
}

// newWalk starts a walk allowed max lookups; 0 means no limit.
func newWalk(max int) *walk { return &walk{seen: map[string]bool{}, capped: max > 0, left: max} }

// within reports whether the object id, of the given kind (page, database,
// data_source or block), is an allowed ID or sits under one. It returns true
// when no token limits the call. A parent the user cannot open counts as
// outside. It returns errTooDeep or errOverBudget when it cannot tell.
// ponytail: one API call per level; cache across calls if deep trees get slow.
func (n *Notion) within(ctx context.Context, c tools.Creds, kind, id string, w *walk) (bool, error) {
	s, limited := tools.ScopeOf(ctx)
	if !limited {
		return true, nil
	}
	allowed, _ := s.([]string)
	var path []string
	for depth := 0; depth < maxDepth; depth++ {
		nid, err := normID(id)
		if err != nil {
			return false, err
		}
		if ok, known := w.seen[nid]; known {
			return mark(w.seen, path, ok), nil
		}
		path = append(path, nid)
		if slices.Contains(allowed, nid) {
			return mark(w.seen, path, true), nil
		}
		if w.capped {
			if w.left == 0 {
				return false, errOverBudget
			}
			w.left--
		}
		var p parent
		switch kind {
		case "page":
			var pg page
			pg, err = n.getPage(ctx, c, nid)
			p = pg.Parent
		case "database":
			var d database
			d, err = n.getDatabase(ctx, c, nid)
			p = d.Parent
		case "data_source":
			var d dataSource
			d, err = n.getDataSource(ctx, c, nid)
			p = d.Parent
		case "block":
			var b struct {
				Parent parent `json:"parent"`
			}
			_, err = n.do(ctx, c, "GET", "/blocks/"+nid, nil, &b)
			p = b.Parent
		default:
			return mark(w.seen, path, false), nil
		}
		switch {
		case err == nil:
		case depth > 0 && (errors.Is(err, errNotFound) || errors.Is(err, errForbidden)):
			// A parent the user cannot open is not a way into the scope.
			return mark(w.seen, path, false), nil
		default:
			return false, err
		}
		switch p.Type {
		case "page_id":
			kind, id = "page", p.PageID
		case "database_id":
			kind, id = "database", p.DatabaseID
		case "data_source_id":
			// A page in a database: the database itself may be the allowed one.
			if db, err := normID(p.DatabaseID); err == nil && slices.Contains(allowed, db) {
				return mark(w.seen, path, true), nil
			}
			kind, id = "data_source", p.DataSourceID
		case "block_id":
			kind, id = "block", p.BlockID
		default: // workspace, or a parent the API does not name
			return mark(w.seen, path, false), nil
		}
	}
	return false, errTooDeep
}

func mark(seen map[string]bool, path []string, ok bool) bool {
	for _, id := range path {
		seen[id] = ok
	}
	return ok
}

// require refuses the call unless the object is within the token's scope.
func (n *Notion) require(ctx context.Context, c tools.Creds, tool, kind, id string) error {
	ok, err := n.within(ctx, c, kind, id, newWalk(0))
	switch {
	case errors.Is(err, errTooDeep):
		return tools.Refuse("%s: %s %s sits more than %d levels below anything in this token's scope, so valetkey cannot check it", tool, kind, id, maxDepth)
	case err != nil:
		return err
	case !ok:
		return tools.Refuse("%s: %s %s is outside this token's scope; it reaches only the pages and databases its scope lists, and what is under them", tool, kind, id)
	}
	return nil
}

var objectTag = regexp.MustCompile(`(?i)<\s*/?\s*(page|database|data-source)\b`)

// requireNoObjectTags refuses markdown that names other pages or databases as
// objects while a token limits the call: what Notion does with such a tag on a
// page outside the scope is not something valetkey can check.
func requireNoObjectTags(ctx context.Context, tool, md string) error {
	if _, limited := tools.ScopeOf(ctx); limited && objectTag.MatchString(md) {
		return tools.Refuse("%s: markdown with <page> or <database> tags is not allowed for this token; write links as [text](url)", tool)
	}
	return nil
}
