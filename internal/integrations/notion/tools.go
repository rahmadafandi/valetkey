package notion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func object(desc string) map[string]any { return map[string]any{"type": "object", "description": desc} }
func array(desc string) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "object"}}
}
func enum(desc string, vals ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": vals}
}

func (n *Notion) Tools() []tools.Tool {
	return []tools.Tool{
		{
			Name: "notion_search",
			Description: "Search Notion pages and databases you can open, by title (read-only). " +
				"Each result gives its ID for notion_page_get, notion_database_query or notion_page_create.",
			Schema: tools.Object(map[string]any{
				"query": tools.Str("words in the title; empty lists recently edited items"),
				"kind":  enum("only pages or only databases; omit for both", "page", "database"),
			}),
			Run: n.search,
		},
		{
			Name: "notion_page_get",
			Description: "Read one Notion page (read-only): its title, properties and content as markdown. " +
				"Takes a page ID or a Notion link.",
			Schema: tools.Object(map[string]any{"page_id": tools.Str("page ID or Notion link")}, "page_id"),
			Run:    n.pageGet,
		},
		{
			Name: "notion_database_query",
			Description: "List the rows of a Notion database (read-only), with their properties. " +
				"filter and sorts take Notion's data source query JSON, for example " +
				`{"property":"Status","status":{"equals":"Done"}} and [{"property":"Due","direction":"ascending"}].`,
			Schema: tools.Object(map[string]any{
				"database_id":    tools.Str("database ID or Notion link"),
				"data_source_id": tools.Str("only for a database with several data sources"),
				"filter":         object("Notion filter object"),
				"sorts":          array("Notion sort objects"),
				"page_size":      tools.Int("rows to return (default 20, max 50)"),
				"start_cursor":   tools.Str("next_cursor from an earlier call, to read on"),
			}, "database_id"),
			Run: n.databaseQuery,
		},
		{
			Name: "notion_page_create",
			Description: "Create a Notion page under a page or in a database, with a title and markdown content. " +
				"In a database only the title property is set.",
			Schema: tools.Object(map[string]any{
				"parent_id":      tools.Str("ID or link of the page or database to create it in"),
				"parent_type":    enum("what parent_id is", "page", "database"),
				"data_source_id": tools.Str("only for a database with several data sources"),
				"title":          tools.Str("page title"),
				"markdown":       tools.Str("page content as markdown"),
			}, "parent_id", "parent_type", "title"),
			Destructive: true,
			Run:         n.pageCreate,
		},
		{
			Name:        "notion_page_append",
			Description: "Add markdown content to the end of a Notion page. Existing content is left as it is.",
			Schema: tools.Object(map[string]any{
				"page_id":  tools.Str("page ID or Notion link"),
				"markdown": tools.Str("content to add, as markdown"),
			}, "page_id", "markdown"),
			Destructive: true,
			Run:         n.pageAppend,
		},
	}
}

// searchLookups caps the parent lookups one search may make to check its
// results against a token's scope, so a search stays well inside Notion's
// rate limit and the tool timeout.
const searchLookups = 40

func (n *Notion) search(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
	var a struct {
		Query string `json:"query"`
		Kind  string `json:"kind"`
	}
	if err := tools.Args(raw, &a); err != nil {
		return "", err
	}
	body := map[string]any{"query": a.Query, "page_size": 20}
	switch a.Kind {
	case "":
	case "page":
		body["filter"] = map[string]string{"property": "object", "value": "page"}
	case "database":
		body["filter"] = map[string]string{"property": "object", "value": "data_source"}
	default:
		return "", errors.New(`kind must be "page" or "database"`)
	}
	var r struct {
		Results []json.RawMessage `json:"results"`
	}
	if _, err := n.do(ctx, c, http.MethodPost, "/search", body, &r); err != nil {
		return "", err
	}
	w := newWalk(searchLookups)
	var lines []string
	hidden, unchecked := 0, 0
	for _, item := range r.Results {
		var o struct {
			Object string `json:"object"`
		}
		json.Unmarshal(item, &o)
		var kind, id, line string
		switch o.Object {
		case "page":
			var p page
			json.Unmarshal(item, &p)
			kind, id = "page", p.ID
			line = fmt.Sprintf("page %s %q %s", p.ID, p.title(), p.URL)
		case "data_source":
			var d dataSource
			json.Unmarshal(item, &d)
			kind, id = "data_source", d.ID
			line = fmt.Sprintf("database %s %q (data source %s)", d.Parent.DatabaseID, d.Title.String(), d.ID)
		default:
			continue
		}
		ok, err := n.within(ctx, c, kind, id, w)
		switch {
		case errors.Is(err, errOverBudget) || errors.Is(err, errTooDeep):
			unchecked++
			continue
		case errors.Is(err, errNotFound) || errors.Is(err, errForbidden):
			hidden++
			continue
		case err != nil:
			return "", err
		}
		if !ok {
			hidden++
			continue
		}
		lines = append(lines, line)
	}
	out := strings.Join(lines, "\n")
	if len(lines) == 0 {
		out = "nothing found"
	}
	if hidden > 0 {
		out += fmt.Sprintf("\n(%d more results are outside this token's scope)", hidden)
	}
	if unchecked > 0 {
		out += fmt.Sprintf("\n(%d more results were not shown: checking them against this token's scope would take too many calls; search with more words)", unchecked)
	}
	return out, nil
}

// properties renders a page's properties, title first, one per line.
func properties(p page) string {
	names := make([]string, 0, len(p.Properties))
	for k := range p.Properties {
		names = append(names, k)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, k := range names {
		if v := propText(p.Properties[k]); v != "" {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	return b.String()
}

func (n *Notion) pageGet(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
	var a struct {
		PageID string `json:"page_id"`
	}
	if err := tools.Args(raw, &a); err != nil {
		return "", err
	}
	id, err := normID(a.PageID)
	if err != nil {
		return "", err
	}
	if err := n.require(ctx, c, "notion_page_get", "page", id); err != nil {
		return "", err
	}
	p, err := n.getPage(ctx, c, id)
	if err != nil {
		return "", err
	}
	var md struct {
		Markdown  string `json:"markdown"`
		Truncated bool   `json:"truncated"`
	}
	if _, err := n.do(ctx, c, http.MethodGet, "/pages/"+id+"/markdown", nil, &md); err != nil {
		return "", err
	}
	out := fmt.Sprintf("%s\n%s\n%s\n%s", p.title(), p.URL, properties(p), md.Markdown)
	if p.InTrash {
		out = "(this page is in the trash)\n" + out
	}
	if md.Truncated {
		out += "\n(the page is too long; Notion returned only the first part)"
	}
	return out, nil
}

func (n *Notion) databaseQuery(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
	var a struct {
		DatabaseID   string          `json:"database_id"`
		DataSourceID string          `json:"data_source_id"`
		Filter       json.RawMessage `json:"filter"`
		Sorts        json.RawMessage `json:"sorts"`
		PageSize     int             `json:"page_size"`
		StartCursor  string          `json:"start_cursor"`
	}
	if err := tools.Args(raw, &a); err != nil {
		return "", err
	}
	id, err := normID(a.DatabaseID)
	if err != nil {
		return "", err
	}
	ds, err := n.dataSourceOf(ctx, c, id, a.DataSourceID)
	if err != nil {
		return "", err
	}
	// Checked from the data source up, so a scope may list the data source,
	// its database, or a page above them.
	if err := n.require(ctx, c, "notion_database_query", "data_source", ds); err != nil {
		return "", err
	}
	if a.PageSize <= 0 {
		a.PageSize = 20
	}
	body := map[string]any{"page_size": min(a.PageSize, 50)}
	if len(a.Filter) > 0 && string(a.Filter) != "null" {
		body["filter"] = a.Filter
	}
	if len(a.Sorts) > 0 && string(a.Sorts) != "null" {
		body["sorts"] = a.Sorts
	}
	if a.StartCursor != "" {
		body["start_cursor"] = a.StartCursor
	}
	var r struct {
		Results    []page `json:"results"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	if _, err := n.do(ctx, c, http.MethodPost, "/data_sources/"+ds+"/query", body, &r); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, p := range r.Results {
		fmt.Fprintf(&b, "%s %s\n%s\n", p.ID, p.URL, properties(p))
	}
	if len(r.Results) == 0 {
		b.WriteString("no rows\n")
	}
	if r.HasMore {
		fmt.Fprintf(&b, "more rows: pass start_cursor %q", r.NextCursor)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func titleValue(t string) map[string]any {
	return map[string]any{"title": []map[string]any{{"type": "text", "text": map[string]string{"content": t}}}}
}

func (n *Notion) pageCreate(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
	var a struct {
		ParentID     string `json:"parent_id"`
		ParentType   string `json:"parent_type"`
		DataSourceID string `json:"data_source_id"`
		Title        string `json:"title"`
		Markdown     string `json:"markdown"`
	}
	if err := tools.Args(raw, &a); err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Title) == "" {
		return "", errors.New("title is required")
	}
	if err := requireNoObjectTags(ctx, "notion_page_create", a.Markdown); err != nil {
		return "", err
	}
	id, err := normID(a.ParentID)
	if err != nil {
		return "", err
	}
	body := map[string]any{}
	switch a.ParentType {
	case "page":
		if err := n.require(ctx, c, "notion_page_create", "page", id); err != nil {
			return "", err
		}
		body["parent"] = map[string]string{"type": "page_id", "page_id": id}
		body["properties"] = map[string]any{"title": titleValue(a.Title)}
	case "database":
		dsID, err := n.dataSourceOf(ctx, c, id, a.DataSourceID)
		if err != nil {
			return "", err
		}
		if err := n.require(ctx, c, "notion_page_create", "data_source", dsID); err != nil {
			return "", err
		}
		ds, err := n.getDataSource(ctx, c, dsID)
		if err != nil {
			return "", err
		}
		titleProp := ""
		for name, p := range ds.Properties {
			if p.Type == "title" {
				titleProp = name
			}
		}
		if titleProp == "" {
			return "", fmt.Errorf("database %s has no title property", id)
		}
		body["parent"] = map[string]string{"type": "data_source_id", "data_source_id": dsID}
		body["properties"] = map[string]any{titleProp: titleValue(a.Title)}
	default:
		return "", errors.New(`parent_type must be "page" or "database"`)
	}
	if a.Markdown != "" {
		body["markdown"] = a.Markdown
	}
	var p page
	if _, err := n.do(ctx, c, http.MethodPost, "/pages", body, &p); err != nil {
		return "", err
	}
	return fmt.Sprintf("created page %s %s", p.ID, p.URL), nil
}

func (n *Notion) pageAppend(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
	var a struct {
		PageID   string `json:"page_id"`
		Markdown string `json:"markdown"`
	}
	if err := tools.Args(raw, &a); err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Markdown) == "" {
		return "", errors.New("markdown is required")
	}
	id, err := normID(a.PageID)
	if err != nil {
		return "", err
	}
	if err := requireNoObjectTags(ctx, "notion_page_append", a.Markdown); err != nil {
		return "", err
	}
	if err := n.require(ctx, c, "notion_page_append", "page", id); err != nil {
		return "", err
	}
	// ponytail: insert_content is Notion's simplest append and still supported;
	// move to update_content if Notion retires it.
	body := map[string]any{"type": "insert_content", "insert_content": map[string]any{
		"content": a.Markdown, "position": map[string]string{"type": "end"}}}
	if _, err := n.do(ctx, c, http.MethodPatch, "/pages/"+id+"/markdown", body, nil); err != nil {
		return "", err
	}
	return "added to page " + id, nil
}
