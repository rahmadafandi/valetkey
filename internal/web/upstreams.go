package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/proxy"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

const (
	upstreamNonceCookie = "vk_upstream_nonce"
	upstreamStateTTL    = 10 * time.Minute
)

var (
	upstreamNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	headerNameRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	authLabels     = map[string]string{"token": "Signs in with a token", "oauth": "Signs in on its own page", "none": "No sign-in"}
)

// upstreamState travels through the server's sign-in page inside the signed
// OAuth state: only which upstream, and the nonce binding it to this browser.
type upstreamState struct {
	UpstreamID string `json:"u"`
	Nonce      string `json:"n"`
}

func (h *Web) upstreamRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /upstreams", h.upstreams)
	mux.HandleFunc("POST /upstreams", h.addUpstream)
	mux.HandleFunc("GET /upstreams/{id}", h.upstreamPage)
	mux.HandleFunc("POST /upstreams/{id}/token", h.upstreamToken)
	mux.HandleFunc("POST /upstreams/{id}/oauth", h.upstreamOAuth)
	mux.HandleFunc("GET /upstreams/{id}/callback", h.upstreamCallback)
	mux.HandleFunc("POST /upstreams/{id}/refresh", h.refreshUpstream)
	mux.HandleFunc("POST /upstreams/{id}/approve", h.approveUpstream)
	mux.HandleFunc("POST /upstreams/{id}/delete", h.deleteUpstream)
}

// upstreamFor checks the Origin of a POST and the session, then loads the
// upstream named in the path for that user only. It writes the refusal itself.
func (h *Web) upstreamFor(w http.ResponseWriter, r *http.Request) (store.User, store.Upstream, bool) {
	if r.Method == http.MethodPost && r.Header.Get("Origin") != h.PublicURL {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return store.User{}, store.Upstream{}, false
	}
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return store.User{}, store.Upstream{}, false
	}
	up, err := h.Auth.Store.GetUpstream(r.Context(), u.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return store.User{}, store.Upstream{}, false
	}
	if err != nil {
		h.fail(w, err)
		return store.User{}, store.Upstream{}, false
	}
	if r.Method == http.MethodPost && r.ParseForm() != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return store.User{}, store.Upstream{}, false
	}
	return u, up, true
}

type upstreamRow struct {
	store.Upstream
	AuthLabel string
	Approved  int
}

func (h *Web) upstreams(w http.ResponseWriter, r *http.Request) {
	u, ok := h.Auth.WebUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	h.renderUpstreams(w, r, u, map[string]any{"Auth": "token"}, http.StatusOK)
}

// renderUpstreams shows the user's servers and the add form; form carries a
// rejected submission back (Name, URL, Auth, Error).
func (h *Web) renderUpstreams(w http.ResponseWriter, r *http.Request, u store.User, form map[string]any, status int) {
	list, err := h.Auth.Store.ListUpstreams(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	approved, err := h.Auth.Store.UserTools(r.Context(), u.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	count := map[string]int{}
	for _, t := range approved {
		count[t.Upstream.ID]++
	}
	rows := make([]upstreamRow, len(list))
	for i, up := range list {
		rows[i] = upstreamRow{up, authLabels[up.Auth], count[up.ID]}
	}
	form["Upstreams"], form["Email"], form["Max"] = rows, u.Email, store.MaxUpstreams
	render(w, status, "upstreams", form)
}

func (h *Web) addUpstream(w http.ResponseWriter, r *http.Request) {
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
	name, rawURL, kind := strings.TrimSpace(r.PostForm.Get("name")), strings.TrimSpace(r.PostForm.Get("url")), r.PostForm.Get("auth")
	form := map[string]any{"Name": name, "URL": rawURL, "Auth": kind}
	reject := func(msg string) {
		form["Error"] = msg
		h.renderUpstreams(w, r, u, form, http.StatusBadRequest)
	}
	if !upstreamNameRE.MatchString(name) {
		reject("The name needs 1 to 24 lowercase letters, digits or dashes, starting with a letter or digit.")
		return
	}
	if _, ok := authLabels[kind]; !ok {
		reject("Pick how this server signs you in.")
		return
	}
	if _, err := h.Guard.CheckURL(rawURL); err != nil {
		reject("valetkey cannot use this address: " + err.Error() + ".")
		return
	}
	up, err := h.Auth.Store.CreateUpstream(r.Context(), store.Upstream{UserID: u.ID, Name: name, URL: rawURL, Auth: kind})
	switch {
	case errors.Is(err, store.ErrLimit):
		reject("You already have " + strconv.Itoa(store.MaxUpstreams) + " servers, the most valetkey keeps for one person. Remove one to add another.")
		return
	case errors.Is(err, store.ErrNameTaken):
		reject("You already have a server named " + name + ". Pick another name.")
		return
	case err != nil:
		h.fail(w, err)
		return
	}
	h.Log.Info("upstream added", "user", u.Email, "upstream", up.ID, "name", up.Name, "auth", up.Auth)
	switch kind {
	case "token":
		http.Redirect(w, r, "/upstreams/"+up.ID, http.StatusSeeOther)
	case "oauth":
		h.startOAuth(w, r, u, up, "", "")
	default:
		h.review(w, r, u, up, tools.Creds{}, "", http.StatusOK)
	}
}

type approvedRow struct {
	store.UpstreamTool
	Prefixed string
}

// renderUpstream shows one server: its sign-in, its approved tools and removal.
// data may carry Error, Header, NeedClient, ClientHost and TokenHost.
func (h *Web) renderUpstream(w http.ResponseWriter, r *http.Request, u store.User, up store.Upstream, data map[string]any, status int) {
	ts, err := h.Auth.Store.ApprovedTools(r.Context(), u.ID, up.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	rows := make([]approvedRow, len(ts))
	for i, t := range ts {
		rows[i].UpstreamTool = t
		rows[i].Prefixed, _ = proxy.ToolName(up.Name, t.Name)
	}
	signedIn := up.Auth == "none"
	if !signedIn {
		_, err := h.Creds.Load(r.Context(), u.ID, proxy.CredsSystem(up.ID))
		if err != nil && !errors.Is(err, tools.ErrNotConnected) {
			h.fail(w, err)
			return
		}
		signedIn = err == nil
	}
	if data["Header"] == nil {
		data["Header"] = "Authorization"
	}
	data["Email"], data["Up"], data["AuthLabel"], data["Tools"], data["SignedIn"] = u.Email, up, authLabels[up.Auth], rows, signedIn
	data["Callback"] = h.PublicURL + "/upstreams/" + up.ID + "/callback"
	render(w, status, "upstream", data)
}

func (h *Web) upstreamPage(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	h.renderUpstream(w, r, u, up, map[string]any{}, http.StatusOK)
}

func (h *Web) upstreamToken(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	header, value := strings.TrimSpace(r.PostForm.Get("header")), strings.TrimSpace(r.PostForm.Get("value"))
	if header == "" {
		header = "Authorization"
	}
	data := map[string]any{"Header": header}
	reject := func(msg string) {
		data["Error"] = msg
		h.renderUpstream(w, r, u, up, data, http.StatusBadRequest)
	}
	switch {
	case up.Auth != "token":
		reject("This server does not sign in with a token.")
		return
	case !headerNameRE.MatchString(header):
		reject("The header name can only hold letters, digits and dashes.")
		return
	case value == "":
		reject("Enter the token to send.")
		return
	}
	c := tools.Creds{"header": header, "value": value}
	cands, skipped, err := h.Proxy.Fetch(r.Context(), up, c)
	if err != nil {
		reject(h.reason(u, up, "tool list", err))
		return
	}
	if err := h.Creds.Save(r.Context(), u.ID, proxy.CredsSystem(up.ID), c); err != nil {
		h.fail(w, err)
		return
	}
	h.Log.Info("upstream signed in", "user", u.Email, "upstream", up.ID, "auth", "token")
	h.renderReview(w, r, u, up, cands, skipped, "", http.StatusOK)
}

func (h *Web) upstreamOAuth(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	if up.Auth != "oauth" {
		h.renderUpstream(w, r, u, up, map[string]any{"Error": "This server does not sign in on its own page."}, http.StatusBadRequest)
		return
	}
	h.startOAuth(w, r, u, up, strings.TrimSpace(r.PostForm.Get("client_id")), strings.TrimSpace(r.PostForm.Get("client_secret")))
}

// startOAuth binds a signed state to this browser with a nonce cookie and
// sends the browser to the server's sign-in page.
func (h *Web) startOAuth(w http.ResponseWriter, r *http.Request, u store.User, up store.Upstream, clientID, clientSecret string) {
	st := upstreamState{UpstreamID: up.ID, Nonce: rand.Text()}
	state, err := h.Auth.Signer.Sign("upstream-oauth", st, upstreamStateTTL)
	if err != nil {
		h.fail(w, err)
		return
	}
	authURL, err := h.Proxy.StartOAuth(r.Context(), u.ID, up, clientID, clientSecret, state)
	var need *proxy.NeedClientError
	if errors.As(err, &need) {
		h.renderUpstream(w, r, u, up, map[string]any{"NeedClient": true, "ClientHost": need.Host, "TokenHost": need.TokenHost}, http.StatusOK)
		return
	}
	if err != nil {
		h.renderUpstream(w, r, u, up, map[string]any{"Error": h.reason(u, up, "sign-in start", err)}, http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: upstreamNonceCookie, Value: st.Nonce, Path: "/upstreams/",
		MaxAge: int(upstreamStateTTL.Seconds()), HttpOnly: true, Secure: h.secure(), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Web) upstreamCallback(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	reject := func(msg string) {
		h.renderUpstream(w, r, u, up, map[string]any{"Error": msg}, http.StatusBadRequest)
	}
	q := r.URL.Query()
	var st upstreamState
	if err := h.Auth.Signer.Verify("upstream-oauth", q.Get("state"), &st); err != nil {
		reject("This sign-in expired or is not valid. Start it again below.")
		return
	}
	ck, err := r.Cookie(upstreamNonceCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(st.Nonce)) != 1 {
		reject("This sign-in was started in another browser. Start it again below.")
		return
	}
	if st.UpstreamID != up.ID {
		reject("This sign-in was for another server. Start it again below.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: upstreamNonceCookie, Path: "/upstreams/", MaxAge: -1})
	if e := q.Get("error"); e != "" {
		h.Log.Warn("upstream sign-in refused", "user", u.Email, "upstream", up.ID, "error", e)
		msg, ok := callbackErrors[e]
		if !ok {
			msg = "The sign-in did not finish. Start it again below."
		}
		reject(msg)
		return
	}
	if err := h.Proxy.FinishOAuth(r.Context(), u.ID, up, q.Get("code")); err != nil {
		reject(h.reason(u, up, "sign-in finish", err))
		return
	}
	h.Log.Info("upstream signed in", "user", u.Email, "upstream", up.ID, "auth", "oauth")
	c, ok := h.login(w, r, u, up)
	if !ok {
		return
	}
	h.review(w, r, u, up, c, "", http.StatusOK)
}

func (h *Web) refreshUpstream(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	c, ok := h.login(w, r, u, up)
	if !ok {
		return
	}
	h.review(w, r, u, up, c, "", http.StatusOK)
}

func (h *Web) approveUpstream(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	c, ok := h.login(w, r, u, up)
	if !ok {
		return
	}
	cands, skipped, err := h.Proxy.Fetch(r.Context(), up, c)
	if err != nil {
		h.renderUpstream(w, r, u, up, map[string]any{"Error": h.reason(u, up, "tool list", err)}, http.StatusBadRequest)
		return
	}
	// Approve exactly the set the user was shown; anything else goes back for review.
	if proxy.Digest(cands) != r.PostForm.Get("digest") {
		h.renderReview(w, r, u, up, cands, skipped, "The server changed its tools while you were reviewing. Check the list again.", http.StatusConflict)
		return
	}
	if err := h.Auth.Store.ApproveTools(r.Context(), u.ID, up.ID, proxy.Snapshot(cands)); err != nil {
		h.fail(w, err)
		return
	}
	h.Log.Info("upstream tools approved", "user", u.Email, "upstream", up.ID, "tools", len(cands))
	http.Redirect(w, r, "/upstreams/"+up.ID, http.StatusSeeOther)
}

func (h *Web) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	u, up, ok := h.upstreamFor(w, r)
	if !ok {
		return
	}
	if err := h.Auth.Store.DeleteUpstream(r.Context(), u.ID, up.ID); err != nil {
		h.fail(w, err)
		return
	}
	h.Log.Info("upstream removed", "user", u.Email, "upstream", up.ID, "name", up.Name)
	http.Redirect(w, r, "/upstreams", http.StatusSeeOther)
}

// login loads the stored login, or shows the server page asking to sign in.
func (h *Web) login(w http.ResponseWriter, r *http.Request, u store.User, up store.Upstream) (tools.Creds, bool) {
	c, err := h.Proxy.Login(r.Context(), u.ID, up)
	switch {
	case errors.Is(err, tools.ErrNotConnected):
		h.renderUpstream(w, r, u, up, map[string]any{"Error": "Sign in to this server first."}, http.StatusBadRequest)
		return nil, false
	case errors.Is(err, upstream.ErrUnauthorized):
		h.renderUpstream(w, r, u, up, map[string]any{"Error": "Your login to this server has run out. Sign in again."}, http.StatusBadRequest)
		return nil, false
	case err != nil:
		h.renderUpstream(w, r, u, up, map[string]any{"Error": h.reason(u, up, "login refresh", err)}, http.StatusBadRequest)
		return nil, false
	}
	return c, true
}

// reason logs why talking to an upstream failed and returns a fixed sentence
// for the page. The error itself stays in the log: it can name the address an
// internal host resolves to.
func (h *Web) reason(u store.User, up store.Upstream, what string, err error) string {
	h.Log.Warn("upstream "+what+" failed", "user", u.Email, "upstream", up.ID, "err", err)
	return proxy.Reason(err)
}

// callbackErrors are the RFC 6749 section 4.1.2.1 codes, in plain words.
var callbackErrors = map[string]string{
	"access_denied":             "You cancelled the sign-in, so valetkey has no login for this server. Start it again below when you are ready.",
	"invalid_request":           "The server's sign-in page refused the request from valetkey. Try again, or check with whoever runs the server.",
	"unauthorized_client":       "The server's sign-in page refused the request from valetkey. Try again, or check with whoever runs the server.",
	"unsupported_response_type": "The server's sign-in page refused the request from valetkey. Try again, or check with whoever runs the server.",
	"invalid_scope":             "The server's sign-in page refused the request from valetkey. Try again, or check with whoever runs the server.",
	"server_error":              "The server's sign-in page had a problem. Try again later.",
	"temporarily_unavailable":   "The server's sign-in page had a problem. Try again later.",
}

// review fetches the server's tools with c and shows them for approval.
func (h *Web) review(w http.ResponseWriter, r *http.Request, u store.User, up store.Upstream, c tools.Creds, errMsg string, status int) {
	cands, skipped, err := h.Proxy.Fetch(r.Context(), up, c)
	if err != nil {
		h.renderUpstream(w, r, u, up, map[string]any{"Error": h.reason(u, up, "tool list", err)}, http.StatusBadRequest)
		return
	}
	h.renderReview(w, r, u, up, cands, skipped, errMsg, status)
}

type reviewRow struct {
	proxy.Candidate
	SchemaText string
	Added      bool
	Changed    string
}

// renderReview lists the fetched tools. Once the user has approved a set, it
// marks what differs and drops tools the server no longer lists, since calls
// to them would fail.
func (h *Web) renderReview(w http.ResponseWriter, r *http.Request, u store.User, up store.Upstream, cands []proxy.Candidate, skipped []proxy.Skipped, errMsg string, status int) {
	data := map[string]any{"Email": u.Email, "Up": up, "Skipped": skipped, "Digest": proxy.Digest(cands), "Error": errMsg}
	var diff proxy.Diff
	if up.ToolsApprovedAt != nil {
		approved, err := h.Auth.Store.ApprovedTools(r.Context(), u.ID, up.ID)
		if err != nil {
			h.fail(w, err)
			return
		}
		diff = proxy.Compare(approved, cands)
		if err := h.Auth.Store.RemoveTools(r.Context(), u.ID, up.ID, diff.Removed); err != nil {
			h.fail(w, err)
			return
		}
		var removed []string
		for _, n := range diff.Removed {
			name, _ := proxy.ToolName(up.Name, n)
			removed = append(removed, name)
		}
		data["Compared"], data["Removed"] = true, removed
		data["Unchanged"] = len(diff.Added)+len(diff.Changed)+len(diff.Removed) == 0
		data["AddedCount"], data["ChangedCount"] = len(diff.Added), len(diff.Changed)
	}
	added := map[string]bool{}
	for _, n := range diff.Added {
		added[n] = true
	}
	changed := map[string]string{}
	for _, c := range diff.Changed {
		var parts []string
		if c.Description {
			parts = append(parts, "description")
		}
		if c.Schema {
			parts = append(parts, "input schema")
		}
		if c.Writes {
			parts = append(parts, "whether it changes things")
		}
		changed[c.Name] = strings.Join(parts, ", ")
	}
	rows := make([]reviewRow, len(cands))
	for i, c := range cands {
		var pretty bytes.Buffer
		if json.Indent(&pretty, c.Schema, "", "  ") != nil {
			pretty.Write(c.Schema)
		}
		rows[i] = reviewRow{Candidate: c, SchemaText: pretty.String(), Added: added[c.Name], Changed: changed[c.Name]}
	}
	data["Tools"] = rows
	render(w, status, "review", data)
}

func (h *Web) secure() bool { return strings.HasPrefix(h.PublicURL, "https://") }
