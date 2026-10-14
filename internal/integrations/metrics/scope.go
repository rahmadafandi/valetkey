package metrics

import (
	"encoding/json"
	"errors"

	promlabels "github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

var promql = parser.NewParser(parser.Options{})

func (m *Metrics) ScopeKey() string { return "metrics" }

type metricsScope struct {
	text     string
	matchers []*promlabels.Matcher
}

// ParseScope reads one set of equality matchers, e.g. {namespace="web"}.
func (m *Metrics) ParseScope(raw json.RawMessage) (any, error) {
	var sel string
	if err := json.Unmarshal(raw, &sel); err != nil {
		return nil, errors.New(`expected one selector string such as {namespace="web"}`)
	}
	ms, err := promql.ParseMetricSelector(sel)
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, errors.New(`expected at least one matcher such as {namespace="web"}`)
	}
	for _, x := range ms {
		if x.Type != promlabels.MatchEqual || x.Name == promlabels.MetricName || x.Value == "" {
			return nil, errors.New(`use only label="value" matchers with a non-empty value, without a metric name`)
		}
	}
	return metricsScope{text: sel, matchers: ms}, nil
}

// CheckScope requires every series selector in the query to carry every scoped
// matcher exactly; a bare metric name (sum(up)) carries none and is refused.
func (m *Metrics) CheckScope(scope any, tool string, args json.RawMessage) error {
	s := scope.(metricsScope)
	var a struct {
		Query string `json:"query"`
	}
	json.Unmarshal(args, &a)
	expr, err := promql.ParseExpr(a.Query)
	if err != nil {
		return tools.Refuse("%s: the query cannot be read (%v); this token allows %s", tool, err, s.text)
	}
	var bad error
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok || bad != nil {
			return nil
		}
		for _, want := range s.matchers {
			if !hasEqual(vs.LabelMatchers, want) {
				bad = tools.Refuse("%s: selector %s is outside this token's scope; every selector needs %s", tool, vs.String(), s.text)
				return nil
			}
		}
		return nil
	})
	return bad
}

func hasEqual(ms []*promlabels.Matcher, want *promlabels.Matcher) bool {
	for _, x := range ms {
		if x.Name == want.Name && x.Type == promlabels.MatchEqual && x.Value == want.Value {
			return true
		}
	}
	return false
}
