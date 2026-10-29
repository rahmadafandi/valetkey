// Package web serves valetkey's small UI: sign-in, connections, catalog.
package web

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/creds"
	"github.com/rahmadafandi/valetkey/internal/netguard"
	"github.com/rahmadafandi/valetkey/internal/proxy"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/ui"
)

//go:embed templates.html
var templatesHTML string

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"list": func(v ...string) []string { return v },
	"head": func() template.HTML { return ui.Head },
	// outcomeLabel turns a stored outcome into the words a page shows.
	"outcomeLabel": func(o string) string { return strings.ReplaceAll(o, "_", " ") },
	// page carries what the shared header needs; here marks the current nav item.
	"page": func(title, email, here string) map[string]string {
		return map[string]string{"Title": title, "Email": email, "Here": here}
	},
}).Parse(templatesHTML))

type CatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Setup       string `json:"setup"`
}

func LoadCatalog(path string) ([]CatalogEntry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c []CatalogEntry
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

type Web struct {
	Auth         *auth.Server
	Creds        creds.Store
	Integrations []tools.Integration
	UserTools    tools.UserIntegrations // the user's own MCP servers' approved tools; may be nil
	Catalog      []CatalogEntry
	AdminEmails  []string
	PublicURL    string
	Log          *slog.Logger
	Proxy        *proxy.Proxy    // the user's own MCP servers
	Guard        *netguard.Guard // checks a server's URL before anything is stored
}

func (h *Web) Routes(mux *http.ServeMux) {
	mux.Handle("GET /fonts/", ui.Fonts())
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /connect/{system}", h.connectForm)
	mux.HandleFunc("POST /connect/{system}", h.connectSubmit)
	mux.HandleFunc("GET /tokens", h.tokens)
	mux.HandleFunc("POST /tokens", h.createToken)
	mux.HandleFunc("POST /tokens/{id}/revoke", h.revokeToken)
	mux.HandleFunc("GET /tokens/{id}/edit", h.editToken)
	mux.HandleFunc("POST /tokens/{id}", h.updateToken)
	mux.HandleFunc("GET /activity", h.activity)
	h.upstreamRoutes(mux)
}

type systemRow struct {
	System, Title string
	Connected     bool
}

func (h *Web) home(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		render(w, http.StatusOK, "signin", nil)
		return
	}
	connected, err := h.Creds.Connected(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	var rows []systemRow
	for _, in := range h.Integrations {
		if len(in.Fields()) > 0 {
			rows = append(rows, systemRow{in.System(), in.Title(), connected[in.System()]})
		}
	}
	calls, err := h.Auth.Store.ListCalls(r.Context(), store.CallFilter{UserID: u.ID, Limit: 5})
	if err != nil {
		h.fail(w, err)
		return
	}
	render(w, http.StatusOK, "home", map[string]any{
		"Email": u.Email, "MCPURL": h.PublicURL + "/mcp", "Systems": rows, "Calls": calls, "Catalog": h.Catalog,
	})
}

// integration finds the credentialed integration named in the URL.
func (h *Web) integration(r *http.Request) (tools.Integration, bool) {
	for _, in := range h.Integrations {
		if in.System() == r.PathValue("system") && len(in.Fields()) > 0 {
			return in, true
		}
	}
	return nil, false
}

func (h *Web) connectForm(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	in, ok := h.integration(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.renderConnect(w, r, u, in, "", http.StatusOK)
}

func (h *Web) renderConnect(w http.ResponseWriter, r *http.Request, u store.User, in tools.Integration, errMsg string, status int) {
	connected, err := h.Creds.Connected(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	var help []string
	if hp, ok := in.(tools.Helper); ok {
		help = hp.Help()
	}
	render(w, status, "connect", map[string]any{
		"Title": in.Title(), "System": in.System(), "Fields": in.Fields(),
		"Connected": connected[in.System()], "Error": errMsg, "Help": help, "Email": u.Email,
	})
}

func (h *Web) connectSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.PublicURL {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	in, ok := h.integration(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("action") == "disconnect" {
		if err := h.Creds.Delete(r.Context(), u.ID, in.System()); err != nil {
			h.fail(w, err)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	c := tools.Creds{}
	for _, f := range in.Fields() {
		v := strings.TrimSpace(r.PostForm.Get(f.Name))
		if v == "" && !f.Optional {
			h.renderConnect(w, r, u, in, f.Label+" is required.", http.StatusBadRequest)
			return
		}
		if v != "" {
			c[f.Name] = v
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := in.Validate(ctx, c); err != nil {
		h.renderConnect(w, r, u, in, "Could not verify these credentials: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.Creds.Save(r.Context(), u.ID, in.System(), c); err != nil {
		h.fail(w, err)
		return
	}
	h.Log.Info("credentials connected", "user", u.Email, "system", in.System())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type toolRow struct {
	Name, Description string
	Destructive       bool
	Checked           bool
}

var expiries = map[string]time.Duration{"7": 7 * 24 * time.Hour, "30": 30 * 24 * time.Hour, "90": 90 * 24 * time.Hour, "0": 0}

// toolRows lists the tools a token may be given: the server's own, then the
// approved tools of the user's own MCP servers.
func (h *Web) toolRows(ctx context.Context, u store.User, checked []string) (native, proxied []toolRow, err error) {
	rows := func(ints []tools.Integration) []toolRow {
		var out []toolRow
		for _, in := range ints {
			for _, t := range in.Tools() {
				out = append(out, toolRow{t.Name, t.Description, t.Destructive, slices.Contains(checked, t.Name)})
			}
		}
		return out
	}
	if h.UserTools != nil {
		ints, err := h.UserTools(ctx, u.ID)
		if err != nil {
			return nil, nil, err
		}
		proxied = rows(ints)
	}
	return rows(h.Integrations), proxied, nil
}

func (h *Web) tokens(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	h.renderTokens(w, r, u, map[string]any{}, http.StatusOK)
}

// renderTokens shows the user's tokens and the create form; form carries a
// rejected submission back (Name, Scope, Expiry, Tools, Error).
func (h *Web) renderTokens(w http.ResponseWriter, r *http.Request, u store.User, form map[string]any, status int) {
	list, err := h.Auth.Store.ListPersonalTokens(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	checked, _ := form["Tools"].([]string)
	native, proxied, err := h.toolRows(r.Context(), u, checked)
	if err != nil {
		h.fail(w, err)
		return
	}
	form["Tokens"], form["ToolRows"], form["ProxiedRows"], form["Email"] = list, native, proxied, u.Email
	if form["Expiry"] == nil {
		form["Expiry"] = "30"
	}
	render(w, status, "tokens", form)
}

func (h *Web) createToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.PublicURL {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	expiry := r.PostForm.Get("expiry")
	n, form, problem, err := h.readTokenForm(r, u)
	form["Expiry"] = expiry
	if err != nil {
		h.fail(w, err)
		return
	}
	if problem == "" {
		var ok bool
		if n.TTL, ok = expiries[expiry]; !ok {
			problem = "Pick an expiry."
		}
	}
	if problem != "" {
		form["Error"] = problem
		h.renderTokens(w, r, u, form, http.StatusBadRequest)
		return
	}
	token, err := h.Auth.CreatePersonalToken(r.Context(), u.ID, n)
	if err != nil {
		form["Error"] = "Could not create the token: " + err.Error()
		h.renderTokens(w, r, u, form, http.StatusBadRequest)
		return
	}
	name := n.Name
	h.Log.Info("personal token created", "user", u.Email, "name", name, "tools", n.Tools)
	w.Header().Set("Cache-Control", "no-store")
	render(w, http.StatusOK, "token_created", map[string]any{"Name": name, "Token": token, "MCPURL": h.PublicURL + "/mcp", "Email": u.Email})
}

// readTokenForm reads the fields the create and edit forms share. form echoes
// them back to the page; problem, when set, says why they cannot be used.
func (h *Web) readTokenForm(r *http.Request, u store.User) (n auth.NewToken, form map[string]any, problem string, err error) {
	n = auth.NewToken{Name: strings.TrimSpace(r.PostForm.Get("name")), Tools: r.PostForm["tools"],
		Scope: []byte(strings.TrimSpace(r.PostForm.Get("scope"))), MaxWritesPerHour: 20, DryRun: r.PostForm.Get("dry_run") == "on"}
	form = map[string]any{"Name": n.Name, "Scope": string(n.Scope), "Tools": n.Tools, "DryRun": n.DryRun, "MaxWrites": r.PostForm.Get("max_writes")}
	if v := strings.TrimSpace(r.PostForm.Get("max_writes")); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 0 || m > 1000 {
			return n, form, "Write limit must be a whole number from 0 (unlimited) to 1000.", nil
		}
		n.MaxWritesPerHour = m
	}
	native, proxied, err := h.toolRows(r.Context(), u, nil)
	if err != nil {
		return n, form, "", err
	}
	known := map[string]bool{}
	for _, t := range append(native, proxied...) {
		known[t.Name] = true
	}
	for _, t := range n.Tools {
		if !known[t] {
			return n, form, "Unknown tool " + t + ".", nil
		}
	}
	return n, form, "", nil
}

func (h *Web) editToken(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	list, err := h.Auth.Store.ListPersonalTokens(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	i := slices.IndexFunc(list, func(t store.PersonalToken) bool { return t.ID == r.PathValue("id") })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	t := list[i]
	h.renderEdit(w, r, u, t.ID, map[string]any{"Name": t.Name, "Scope": string(t.Scope), "Tools": t.Tools,
		"DryRun": t.DryRun, "MaxWrites": strconv.Itoa(t.MaxWritesPerHour)}, http.StatusOK)
}

// renderEdit shows the edit form; form carries the token's fields and Error.
func (h *Web) renderEdit(w http.ResponseWriter, r *http.Request, u store.User, id string, form map[string]any, status int) {
	checked, _ := form["Tools"].([]string)
	native, proxied, err := h.toolRows(r.Context(), u, checked)
	if err != nil {
		h.fail(w, err)
		return
	}
	form["ID"], form["ToolRows"], form["ProxiedRows"], form["Email"] = id, native, proxied, u.Email
	render(w, status, "token_edit", form)
}

func (h *Web) updateToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.PublicURL {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	n, form, problem, err := h.readTokenForm(r, u)
	if err != nil {
		h.fail(w, err)
		return
	}
	if problem == "" {
		err = h.Auth.UpdatePersonalToken(r.Context(), u.ID, id, n)
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			problem = "Could not save the token: " + err.Error()
		}
	}
	if problem != "" {
		form["Error"] = problem
		h.renderEdit(w, r, u, id, form, http.StatusBadRequest)
		return
	}
	h.Log.Info("personal token edited", "user", u.Email, "id", id, "name", n.Name, "tools", n.Tools)
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *Web) revokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.PublicURL {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	err := h.Auth.Store.DeletePersonalToken(r.Context(), u.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	h.Log.Info("personal token revoked", "user", u.Email, "id", r.PathValue("id"))
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (h *Web) fail(w http.ResponseWriter, err error) {
	h.Log.Error("web request failed", "err", err)
	render(w, http.StatusInternalServerError, "error", nil)
}

func render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// activity lists tool calls: the signed-in user's own, or everyone's for an admin.
func (h *Web) activity(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	q := r.URL.Query()
	admin := slices.Contains(h.AdminEmails, u.Email)
	f := store.CallFilter{UserID: u.ID, TokenName: q.Get("token"), Tool: q.Get("tool"), Outcome: q.Get("outcome"), Limit: 200}
	if admin {
		f.UserID, f.Email = "", strings.ToLower(strings.TrimSpace(q.Get("user"))) // empty means everyone
	}
	calls, err := h.Auth.Store.ListCalls(r.Context(), f)
	if err != nil {
		h.fail(w, err)
		return
	}
	filtered := f.TokenName != "" || f.Tool != "" || f.Outcome != "" || f.Email != ""
	render(w, http.StatusOK, "activity", map[string]any{"Email": u.Email, "Calls": calls, "Admin": admin, "Filter": f, "Filtered": filtered})
}
