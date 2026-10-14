package jenkins

import (
	"encoding/json"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestParseScope(t *testing.T) {
	j := &Jenkins{}
	if v, err := j.ParseScope(json.RawMessage(`"deploy-web"`)); err != nil || v.([]string)[0] != "deploy-web" {
		t.Errorf("string: %v %v", v, err)
	}
	if v, err := j.ParseScope(json.RawMessage(`["a","/b/c/"]`)); err != nil || len(v.([]string)) != 2 || v.([]string)[1] != "b/c" {
		t.Errorf("list: %v %v", v, err)
	}
	for _, bad := range []string{`3`, `[""]`, `[]`, `null`, `"https://jenkins.example.com/job/deploy-web"`, `"job/deploy-web"`, `"folder/job/deploy-web"`} {
		if _, err := j.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCheckScope(t *testing.T) {
	j := &Jenkins{}
	scope, err := j.ParseScope(json.RawMessage(`["deploy-web","folder/deep job"]`))
	if err != nil {
		t.Fatal(err)
	}
	for jobURL, ok := range map[string]bool{
		"https://jenkins.example.com/job/deploy-web/":                 true,
		"https://jenkins.example.com/job/folder/job/deep%20job":       true,
		"https://jenkins.example.com/view/all/job/deploy-web":         true,
		"https://jenkins.example.com/ci/job/deploy-web":               true,
		"https://jenkins.example.com/job/deploy-web-canary/":          false,
		"https://jenkins.example.com/job/folder/job/deploy-web":       false,
		"https://jenkins.example.com/job/folder%2Fdeep%20job":         false,
		"https://jenkins.example.com/job/deploy-web/12/":              false,
		"https://jenkins.example.com/job/deploy-web/job/":             false,
		"https://jenkins.example.com/job/deploy-web/../other/":        false,
		"https://jenkins.example.com/job/deploy-web/%2e%2e/job/other": false,
		"https://jenkins.example.com/job/deploy-web/..;/job/other":    false,
		"https://jenkins.example.com/job/deploy-web;x/":               false,
		"https://jenkins.example.com/":                                false,
		"":                                                            false,
		"https://jenkins.example.com/%6Aob/evil/job/deploy-web/":      false,
		"https://jenkins.example.com/j%6Fb/evil/job/deploy-web/":      false,
		"https://jenkins.example.com/JOB/evil/job/deploy-web/":        false,
		"https://jenkins.example.com/Job/deploy-web/":                 false,
		"https://jenkins.example.com/job/%2564eploy-web/":             false,
		"https://jenkins.example.com/job/deploy-web%3F/":              false,
	} {
		args, _ := json.Marshal(map[string]string{"jobURL": jobURL})
		err := j.CheckScope(scope, "jenkins_deploy", args)
		if (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok=%v", jobURL, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%q: not a refusal: %v", jobURL, err)
		}
	}
	if err := j.CheckScope(scope, "jenkins_deploy", nil); !tools.IsRefusal(err) {
		t.Errorf("no arguments: %v", err)
	}
}
