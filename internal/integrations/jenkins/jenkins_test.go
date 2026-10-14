package jenkins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var (
	ctx   = context.Background()
	alice = tools.Creds{"username": "alice", "token": "tok"}
)

const paramsJSON = `{"property":[{"parameterDefinitions":[
 {"name":"VERSION","type":"StringParameterDefinition","defaultParameterValue":{"value":"latest"}},
 {"name":"ENV","type":"ChoiceParameterDefinition","choices":["staging","production"],"defaultParameterValue":{"value":"staging"}}]}]}`

const buildsJSON = `{"builds":[
 {"number":8,"result":null,"building":true,"timestamp":1760400000000,"displayName":"#8","changeSet":{"items":[]}},
 {"number":7,"result":"SUCCESS","building":false,"timestamp":1760396400000,"displayName":"29-441f3f9",
  "changeSet":{"items":[{"commitId":"441f3f9abcdef1234","msg":"fix login","author":{"fullName":"Rahmad"}}]}}]}`

type fakeJenkins struct {
	*httptest.Server
	mu            sync.Mutex
	posted        []string
	queueLocation bool
	queuePolls    int
	buildPolls    int
}

func newFake(t *testing.T) *fakeJenkins {
	f := &fakeJenkins{}
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "tok" {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	record := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Jenkins-Crumb") != "c1" {
			http.Error(w, "no crumb", http.StatusForbidden)
			return
		}
		r.ParseForm()
		f.mu.Lock()
		f.posted = append(f.posted, r.URL.Path+"?"+r.PostForm.Encode())
		f.mu.Unlock()
		if f.queueLocation {
			w.Header().Set("Location", "http://evil.example/queue/item/42/") // only the item id may be trusted
		}
		w.WriteHeader(http.StatusCreated)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /me/api/json", auth(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"id":"alice"}`)) }))
	mux.HandleFunc("GET /crumbIssuer/api/json", auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"crumbRequestField":"Jenkins-Crumb","crumb":"c1"}`))
	}))
	mux.HandleFunc("GET /job/app/api/json", auth(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("tree"), "parameterDefinitions") {
			w.Write([]byte(paramsJSON))
			return
		}
		w.Write([]byte(buildsJSON))
	}))
	mux.HandleFunc("GET /job/app/7/api/json", auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"actions":[{},{"parameters":[{"name":"VERSION","value":"1.2.3"},{"name":"DRY","value":false},{"name":"NOTE","value":null}]}]}`))
	}))
	mux.HandleFunc("GET /queue/item/42/api/json", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.queuePolls++
		n := f.queuePolls
		f.mu.Unlock()
		if n < 2 {
			w.Write([]byte(`{"cancelled":false,"executable":null}`))
			return
		}
		w.Write([]byte(`{"executable":{"number":9,"url":"` + f.URL + `/job/app/9/"}}`))
	}))
	mux.HandleFunc("GET /job/app/9/api/json", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.buildPolls++
		n := f.buildPolls
		f.mu.Unlock()
		if n < 2 {
			w.Write([]byte(`{"building":true,"result":null}`))
			return
		}
		w.Write([]byte(`{"building":false,"result":"FAILURE"}`))
	}))
	mux.HandleFunc("GET /job/app/9/consoleText", auth(func(w http.ResponseWriter, _ *http.Request) {
		for i := 1; i <= 250; i++ {
			fmt.Fprintf(w, "line %d\n", i)
		}
	}))
	mux.HandleFunc("POST /job/app/build", auth(record))
	mux.HandleFunc("POST /job/app/buildWithParameters", auth(record))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func setup(t *testing.T) (*Jenkins, *fakeJenkins) {
	pollEvery = time.Millisecond
	f := newFake(t)
	j, err := New(f.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	return j, f
}

func run(t *testing.T, j *Jenkins, name string, c tools.Creds, args string) (string, error) {
	t.Helper()
	for _, tl := range j.Tools() {
		if tl.Name == name {
			return tl.Run(ctx, c, json.RawMessage(args))
		}
	}
	t.Fatalf("no tool %s", name)
	return "", nil
}

func TestBuilds(t *testing.T) {
	j, f := setup(t)
	out, err := run(t, j, "jenkins_builds", alice, `{"jobURL":"`+f.URL+`/job/app/"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#8 BUILDING", "#7 SUCCESS", "(29-441f3f9)", `441f3f9abc "fix login"`, "by Rahmad"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestJobParams(t *testing.T) {
	j, f := setup(t)
	out, err := run(t, j, "jenkins_job", alice, `{"jobURL":"`+f.URL+`/job/app"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`VERSION (string) default="latest"`, `ENV (choice) default="staging" choices=[staging production]`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDeploy(t *testing.T) {
	j, f := setup(t)
	out, err := run(t, j, "jenkins_deploy", alice, `{"jobURL":"`+f.URL+`/job/app","params":{"VERSION":"1.0","ENV":"production"}}`)
	if err != nil || out != "parameterized build queued" {
		t.Fatalf("with params: %q %v", out, err)
	}
	out, err = run(t, j, "jenkins_deploy", alice, `{"jobURL":"`+f.URL+`/job/app"}`)
	if err != nil || out != "build queued" {
		t.Fatalf("plain: %q %v", out, err)
	}
	want := []string{"/job/app/buildWithParameters?ENV=production&VERSION=1.0", "/job/app/build?"}
	if strings.Join(f.posted, "|") != strings.Join(want, "|") {
		t.Errorf("posted = %v", f.posted)
	}
}

func TestRebuildReplaysParams(t *testing.T) {
	j, f := setup(t)
	if out, err := run(t, j, "jenkins_build_params", alice, `{"jobURL":"`+f.URL+`/job/app","number":7}`); err != nil || out != "VERSION=1.2.3\nDRY=false\nNOTE=(no value)\n" {
		t.Fatalf("build params: %q %v", out, err)
	}
	if _, err := run(t, j, "jenkins_rebuild", alice, `{"jobURL":"`+f.URL+`/job/app","number":7}`); err != nil {
		t.Fatal(err)
	}
	if len(f.posted) != 1 || f.posted[0] != "/job/app/buildWithParameters?DRY=false&VERSION=1.2.3" {
		t.Errorf("posted = %v", f.posted)
	}
}

func TestRefusesForeignJobURL(t *testing.T) {
	j, f := setup(t)
	host := strings.TrimPrefix(f.URL, "http://")
	for _, u := range []string{
		"http://evil.example/job/app",
		"http://" + host + ".evil.example/job/app",
		"http://alice:tok@" + host + "/job/app",
		"https://" + host + "/job/app",
		f.URL + "/job/app?token=x",
		f.URL,
		"not a url",
	} {
		if _, err := j.jobURL(u); err == nil {
			t.Errorf("accepted %q", u)
		}
		if _, err := run(t, j, "jenkins_deploy", alice, `{"jobURL":"`+u+`"}`); err == nil {
			t.Errorf("deploy accepted %q", u)
		}
	}
	if len(f.posted) != 0 {
		t.Errorf("a refused URL still reached Jenkins: %v", f.posted)
	}
}

func TestWrongCredsIsUnauthorized(t *testing.T) {
	j, f := setup(t)
	bob := tools.Creds{"username": "bob", "token": "x"}
	if err := j.Validate(ctx, bob); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("Validate: %v", err)
	}
	if _, err := run(t, j, "jenkins_builds", bob, `{"jobURL":"`+f.URL+`/job/app"}`); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("builds: %v", err)
	}
	if err := j.Validate(ctx, alice); err != nil {
		t.Errorf("Validate alice: %v", err)
	}
}

func TestDestructiveFlags(t *testing.T) {
	j, _ := setup(t)
	got := map[string]bool{}
	for _, tl := range j.Tools() {
		got[tl.Name] = tl.Destructive
	}
	want := map[string]bool{"jenkins_job": false, "jenkins_builds": false, "jenkins_build_params": false, "jenkins_build_wait": false, "jenkins_deploy": true, "jenkins_rebuild": true}
	for k, v := range want {
		if d, ok := got[k]; !ok || d != v {
			t.Errorf("%s: present=%v destructive=%v", k, ok, d)
		}
	}
}

func TestDeployReturnsBuildNumber(t *testing.T) {
	j, f := setup(t)
	f.queueLocation = true
	out, err := run(t, j, "jenkins_deploy", alice, `{"jobURL":"`+f.URL+`/job/app"}`)
	if err != nil || out != "build started: #9 "+f.URL+"/job/app/9/" {
		t.Fatalf("got %q %v", out, err)
	}
	if f.queuePolls != 2 {
		t.Errorf("queue polled %d times, want 2", f.queuePolls)
	}
}

func TestDeployNotStartedInTime(t *testing.T) {
	j, f := setup(t)
	f.queueLocation = true
	defer func(d time.Duration) { startWait = d }(startWait)
	startWait = 0
	out, err := run(t, j, "jenkins_deploy", alice, `{"jobURL":"`+f.URL+`/job/app"}`)
	if err != nil || !strings.Contains(out, "queue item 42") || !strings.Contains(out, "not started") {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestBuildWait(t *testing.T) {
	j, f := setup(t)
	out, err := run(t, j, "jenkins_build_wait", alice, `{"jobURL":"`+f.URL+`/job/app","number":9}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "#9 FAILURE\n") || !strings.HasSuffix(out, "line 250") || !strings.Contains(out, "\nline 51\n") || strings.Contains(out, "line 50\n") {
		t.Errorf("got:\n%s", out)
	}
}

func TestBuildWaitTimesOut(t *testing.T) {
	j, f := setup(t)
	out, err := j.waitBuild(ctx, alice, f.URL+"/job/app", 9, time.Nanosecond)
	if err != nil || !strings.HasPrefix(out, "#9 BUILDING (still running") {
		t.Fatalf("got %q %v", out, err)
	}
}
