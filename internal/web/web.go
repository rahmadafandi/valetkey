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
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

//go:embed templates.html
var templatesHTML string

var tmpl = template.Must(template.New("").Parse(templatesHTML))

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
	Catalog      []CatalogEntry
	PublicURL    string
	Log          *slog.Logger
}

func (h *Web) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /connect/{system}", h.connectForm)
	mux.HandleFunc("POST /connect/{system}", h.connectSubmit)
	mux.HandleFunc("GET /tokens", h.tokens)
	mux.HandleFunc("POST /tokens", h.createToken)
	mux.HandleFunc("POST /tokens/{id}/revoke", h.revokeToken)
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
	render(w, http.StatusOK, "home", map[string]any{
		"Email": u.Email, "MCPURL": h.PublicURL + "/mcp", "Systems": rows, "Catalog": h.Catalog,
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
		"Connected": connected[in.System()], "Error": errMsg, "Help": help,
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

func (h *Web) toolRows(checked []string) []toolRow {
	var rows []toolRow
	for _, in := range h.Integrations {
		for _, t := range in.Tools() {
			rows = append(rows, toolRow{t.Name, t.Description, t.Destructive, slices.Contains(checked, t.Name)})
		}
	}
	return rows
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
	form["Tokens"], form["ToolRows"], form["Email"] = list, h.toolRows(checked), u.Email
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
	name, scope, expiry := strings.TrimSpace(r.PostForm.Get("name")), strings.TrimSpace(r.PostForm.Get("scope")), r.PostForm.Get("expiry")
	picked := r.PostForm["tools"]
	dryRun := r.PostForm.Get("dry_run") == "on"
	form := map[string]any{"Name": name, "Scope": scope, "Expiry": expiry, "Tools": picked, "DryRun": dryRun, "MaxWrites": r.PostForm.Get("max_writes")}
	maxWrites := 20
	if v := strings.TrimSpace(r.PostForm.Get("max_writes")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1000 {
			form["Error"] = "Write limit must be a whole number from 0 (unlimited) to 1000."
			h.renderTokens(w, r, u, form, http.StatusBadRequest)
			return
		}
		maxWrites = n
	}
	known := map[string]bool{}
	for _, t := range h.toolRows(nil) {
		known[t.Name] = true
	}
	for _, t := range picked {
		if !known[t] {
			form["Error"] = "Unknown tool " + t + "."
			h.renderTokens(w, r, u, form, http.StatusBadRequest)
			return
		}
	}
	ttl, ok := expiries[expiry]
	if !ok {
		form["Error"] = "Pick an expiry."
		h.renderTokens(w, r, u, form, http.StatusBadRequest)
		return
	}
	token, err := h.Auth.CreatePersonalToken(r.Context(), u.ID, auth.NewToken{
		Name: name, Tools: picked, Scope: []byte(scope), TTL: ttl, MaxWritesPerHour: maxWrites, DryRun: dryRun})
	if err != nil {
		form["Error"] = "Could not create the token: " + err.Error()
		h.renderTokens(w, r, u, form, http.StatusBadRequest)
		return
	}
	h.Log.Info("personal token created", "user", u.Email, "name", name, "tools", picked)
	w.Header().Set("Cache-Control", "no-store")
	render(w, http.StatusOK, "token_created", map[string]any{"Name": name, "Token": token, "MCPURL": h.PublicURL + "/mcp"})
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
	http.Error(w, "internal error", http.StatusInternalServerError)
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
