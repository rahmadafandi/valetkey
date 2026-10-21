// Package notion exposes Notion search, page and database tools, authenticated
// per user with a Notion personal access token.
package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

// apiVersion is the Notion-Version every request sends.
const apiVersion = "2026-03-11"

type Notion struct {
	base   string // API root, e.g. https://api.notion.com/v1
	client *http.Client
}

func New(baseURL string, insecure bool) *Notion {
	return &Notion{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure)}
}

func (n *Notion) System() string { return "notion" }
func (n *Notion) Title() string  { return "Notion" }

func (n *Notion) Fields() []tools.Field {
	return []tools.Field{{Name: "token", Label: "Personal access token", Secret: true}}
}

func (n *Notion) Help() []string {
	return []string{
		"Open https://www.notion.so/developers/tokens and choose New token.",
		"Name it, keep the Notion API capability, pick an expiry and the workspace, then choose Create token and copy it. Notion shows it only once.",
		"The token acts as you: it reaches every page you can open in Notion. Your workspace may let only owners create tokens; if New token is missing, ask a workspace owner or admin.",
	}
}

// Validate asks Notion who the token belongs to.
func (n *Notion) Validate(ctx context.Context, c tools.Creds) error {
	if strings.TrimSpace(c["token"]) == "" {
		return errors.New("token is required")
	}
	_, err := n.do(ctx, c, http.MethodGet, "/users/me", nil, nil)
	return err
}

var (
	errNotFound  = errors.New("not found, or you cannot open it in Notion")
	errForbidden = errors.New("this token may not do that")
)

// maxBody is the largest response valetkey reads from Notion.
const maxBody = 4 << 20

// do sends one API request. body, when not nil, is sent as JSON; out, when not
// nil, receives the decoded response.
func (n *Notion) do(ctx context.Context, c tools.Creds, method, path string, body, out any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c["token"]))
	req.Header.Set("Notion-Version", apiVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("notion: the answer to %s is larger than %d MiB", path, maxBody>>20)
	}
	switch resp.StatusCode {
	case http.StatusForbidden:
		// Notion answers 403 when the token lacks a capability, not when it is
		// bad, so this must not tell the user to reconnect.
		return nil, fmt.Errorf("notion 403 on %s: %w: %s", path, errForbidden, apiMessage(raw))
	case http.StatusNotFound:
		return nil, fmt.Errorf("notion 404 on %s: %w", path, errNotFound)
	case http.StatusTooManyRequests:
		wait := resp.Header.Get("Retry-After")
		if wait == "" {
			wait = "a few"
		}
		return nil, fmt.Errorf("notion 429: Notion is limiting how fast this token may call it; try again in %s seconds", wait)
	}
	if err := upstream.StatusErr("notion", resp.StatusCode, []byte(apiMessage(raw))); err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("notion: parse %s: %w", path, err)
		}
	}
	return raw, nil
}

// apiMessage pulls the message out of a Notion error body.
func apiMessage(raw []byte) string {
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return string(raw)
}

var idRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}`)

// normID reads a Notion ID, with or without dashes, or the one at the end of a
// Notion link's path (not a ?v= view), as 32 lowercase hex characters.
func normID(s string) (string, error) {
	in := s
	if u, err := url.Parse(strings.TrimSpace(s)); err == nil && u.Host != "" {
		in = u.Path
	}
	m := idRe.FindAllString(in, -1)
	if len(m) == 0 {
		return "", fmt.Errorf("%q is not a Notion ID or link", s)
	}
	return strings.ToLower(strings.ReplaceAll(m[len(m)-1], "-", "")), nil
}

type richText []struct {
	PlainText string `json:"plain_text"`
}

func (r richText) String() string {
	var b strings.Builder
	for _, t := range r {
		b.WriteString(t.PlainText)
	}
	return b.String()
}

// parent is where a Notion object sits.
type parent struct {
	Type         string `json:"type"`
	PageID       string `json:"page_id"`
	DatabaseID   string `json:"database_id"`
	DataSourceID string `json:"data_source_id"`
	BlockID      string `json:"block_id"`
}

type page struct {
	ID         string                     `json:"id"`
	URL        string                     `json:"url"`
	Parent     parent                     `json:"parent"`
	InTrash    bool                       `json:"in_trash"`
	Properties map[string]json.RawMessage `json:"properties"`
}

// title is the text of the page's title property.
func (p page) title() string {
	for _, raw := range p.Properties {
		var v struct {
			Type  string   `json:"type"`
			Title richText `json:"title"`
		}
		if json.Unmarshal(raw, &v) == nil && v.Type == "title" {
			return v.Title.String()
		}
	}
	return ""
}

type database struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	Title       richText `json:"title"`
	Parent      parent   `json:"parent"`
	DataSources []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"data_sources"`
}

type dataSource struct {
	ID         string   `json:"id"`
	Title      richText `json:"title"`
	Parent     parent   `json:"parent"`
	Properties map[string]struct {
		Type string `json:"type"`
	} `json:"properties"`
}

func (n *Notion) getPage(ctx context.Context, c tools.Creds, id string) (page, error) {
	var p page
	_, err := n.do(ctx, c, http.MethodGet, "/pages/"+id, nil, &p)
	return p, err
}

func (n *Notion) getDatabase(ctx context.Context, c tools.Creds, id string) (database, error) {
	var d database
	_, err := n.do(ctx, c, http.MethodGet, "/databases/"+id, nil, &d)
	return d, err
}

func (n *Notion) getDataSource(ctx context.Context, c tools.Creds, id string) (dataSource, error) {
	var d dataSource
	_, err := n.do(ctx, c, http.MethodGet, "/data_sources/"+id, nil, &d)
	return d, err
}

// dataSourceOf picks the database's data source: the only one, or the one named.
func (n *Notion) dataSourceOf(ctx context.Context, c tools.Creds, dbID, want string) (string, error) {
	d, err := n.getDatabase(ctx, c, dbID)
	if err != nil {
		return "", err
	}
	if want != "" {
		w, err := normID(want)
		if err != nil {
			return "", err
		}
		for _, s := range d.DataSources {
			if id, _ := normID(s.ID); id == w {
				return id, nil
			}
		}
		return "", fmt.Errorf("database %s has no data source %s", dbID, want)
	}
	switch len(d.DataSources) {
	case 0:
		return "", fmt.Errorf("database %s has no data source", dbID)
	case 1:
		return normID(d.DataSources[0].ID)
	}
	var names []string
	for _, s := range d.DataSources {
		names = append(names, s.Name+" ("+s.ID+")")
	}
	return "", fmt.Errorf("database %s has several data sources; pass data_source_id, one of: %s", dbID, strings.Join(names, ", "))
}

// propText renders one property value as short text.
func propText(raw json.RawMessage) string {
	var v struct {
		Type        string                  `json:"type"`
		Title       richText                `json:"title"`
		RichText    richText                `json:"rich_text"`
		Number      *float64                `json:"number"`
		Checkbox    bool                    `json:"checkbox"`
		URL         string                  `json:"url"`
		Email       string                  `json:"email"`
		Phone       string                  `json:"phone_number"`
		Select      *struct{ Name string }  `json:"select"`
		Status      *struct{ Name string }  `json:"status"`
		MultiSelect []struct{ Name string } `json:"multi_select"`
		People      []struct{ Name string } `json:"people"`
		Relation    []struct{ ID string }   `json:"relation"`
		Date        *struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"date"`
		Formula *struct {
			String  *string  `json:"string"`
			Number  *float64 `json:"number"`
			Boolean *bool    `json:"boolean"`
		} `json:"formula"`
		CreatedTime    string `json:"created_time"`
		LastEditedTime string `json:"last_edited_time"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	names := func(xs []struct{ Name string }) string {
		var out []string
		for _, x := range xs {
			out = append(out, x.Name)
		}
		return strings.Join(out, ", ")
	}
	switch v.Type {
	case "title":
		return v.Title.String()
	case "rich_text":
		return v.RichText.String()
	case "number":
		if v.Number != nil {
			return fmt.Sprint(*v.Number)
		}
	case "checkbox":
		return fmt.Sprint(v.Checkbox)
	case "url":
		return v.URL
	case "email":
		return v.Email
	case "phone_number":
		return v.Phone
	case "select":
		if v.Select != nil {
			return v.Select.Name
		}
	case "status":
		if v.Status != nil {
			return v.Status.Name
		}
	case "multi_select":
		return names(v.MultiSelect)
	case "people":
		return names(v.People)
	case "relation":
		return fmt.Sprintf("%d linked", len(v.Relation))
	case "date":
		if v.Date != nil {
			if v.Date.End != "" {
				return v.Date.Start + " to " + v.Date.End
			}
			return v.Date.Start
		}
	case "formula":
		switch f := v.Formula; {
		case f == nil:
		case f.String != nil:
			return *f.String
		case f.Number != nil:
			return fmt.Sprint(*f.Number)
		case f.Boolean != nil:
			return fmt.Sprint(*f.Boolean)
		}
	case "created_time":
		return v.CreatedTime
	case "last_edited_time":
		return v.LastEditedTime
	default:
		return "(" + v.Type + ")"
	}
	return ""
}
