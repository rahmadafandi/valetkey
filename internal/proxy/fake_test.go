package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/netguard"
)

type fakeTool struct {
	Name        string
	Description string
	Schema      map[string]any
	Annotations *mcp.ToolAnnotations
}

type fakeOpts struct {
	Token    string // when set, requests without Header: Token get 401
	Header   string // defaults to Authorization
	PageSize int
	Tools    []fakeTool
}

type fake struct {
	URL   string
	Guard *netguard.Guard

	opts       fakeOpts
	mu         sync.Mutex
	tools      []fakeTool
	calls      map[string]int
	lastArgs   string
	userAgent  string
	auth       string
	clientName string
}

func newFake(t *testing.T, opts fakeOpts) *fake {
	t.Helper()
	if opts.Header == "" {
		opts.Header = "Authorization"
	}
	f := &fake{opts: opts, tools: opts.Tools, calls: map[string]int{}, Guard: &netguard.Guard{AllowHosts: []string{"127.0.0.1"}}}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return f.server() }, &mcp.StreamableHTTPOptions{Stateless: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		type impl struct {
			Name string `json:"name"`
		}
		// clientInfo travels in initialize, or in _meta of every request under the 2026-07-28 protocol.
		var msg struct {
			Params struct {
				ClientInfo impl `json:"clientInfo"`
				Meta       struct {
					ClientInfo impl `json:"io.modelcontextprotocol/clientInfo"`
				} `json:"_meta"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &msg)
		f.mu.Lock()
		f.userAgent, f.auth = r.UserAgent(), r.Header.Get(opts.Header)
		if n := msg.Params.ClientInfo.Name + msg.Params.Meta.ClientInfo.Name; n != "" {
			f.clientName = n
		}
		f.mu.Unlock()
		if opts.Token != "" && r.Header.Get(opts.Header) != opts.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f.URL = srv.URL + "/mcp"
	return f
}

func (f *fake) setTools(ts []fakeTool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools = ts
}

func (f *fake) seen() (userAgent, auth, clientName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userAgent, f.auth, f.clientName
}

func (f *fake) called(name string) (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name], f.lastArgs
}

func (f *fake) server() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"},
		&mcp.ServerOptions{PageSize: f.opts.PageSize, Logger: slog.New(slog.DiscardHandler)})
	f.mu.Lock()
	ts := f.tools
	f.mu.Unlock()
	for _, ft := range ts {
		schema := ft.Schema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		srv.AddTool(&mcp.Tool{Name: ft.Name, Description: ft.Description, InputSchema: schema, Annotations: ft.Annotations},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.mu.Lock()
				f.calls[req.Params.Name]++
				f.lastArgs = string(req.Params.Arguments)
				f.mu.Unlock()
				switch req.Params.Name {
				case "picture":
					return &mcp.CallToolResult{Content: []mcp.Content{
						&mcp.ImageContent{Data: []byte("png"), MIMEType: "image/png"},
						&mcp.TextContent{Text: "a picture"},
					}}, nil
				case "fail":
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "boom"}}, IsError: true}, nil
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo " + string(req.Params.Arguments)}}}, nil
			})
	}
	return srv
}
