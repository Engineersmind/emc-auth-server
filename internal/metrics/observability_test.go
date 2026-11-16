package metrics

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// repoRel resolves a path relative to the repository root — go test runs with
// the package directory (internal/metrics) as the working directory.
func repoRel(elem ...string) string {
	return filepath.Join(append([]string{"..", ".."}, elem...)...)
}

var emcTokenRe = regexp.MustCompile(`emc_auth_[a-z0-9_]+`)
var nodeTokenRe = regexp.MustCompile(`node_[a-z0-9_]+`)
var alertNameRe = regexp.MustCompile(`^\s*-\s*alert:\s*([A-Za-z0-9_]+)`)
var exprLineRe = regexp.MustCompile(`^\s*expr:\s*(.*)$`)
var seriesLineRe = regexp.MustCompile(`^\s*-\s*series:\s*(.*)$`)
var uidLineRe = regexp.MustCompile(`^\s*uid:\s*([A-Za-z0-9_-]+)`)

// knownMetricNames builds the authoritative set of emc_auth_* series names
// from the Go source itself: every promauto.New* opts literal with
// Namespace: "emc_auth" contributes Namespace_Name, plus the pool collector's
// PoolMetricNames. Nothing is hand-kept — a metric deleted from metrics.go or
// renamed there stops being "known" the moment the source changes.
func knownMetricNames(t *testing.T) (names, histograms map[string]bool) {
	t.Helper()
	names = map[string]bool{}
	histograms = map[string]bool{}

	fset := token.NewFileSet()
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob *.go: %v", err)
	}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "promauto" || !strings.HasPrefix(sel.Sel.Name, "New") {
				return true
			}
			lit, ok := call.Args[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			var name, ns string
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				bl, ok := kv.Value.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(bl.Value)
				if err != nil {
					continue
				}
				switch key.Name {
				case "Name":
					name = v
				case "Namespace":
					ns = v
				}
			}
			if ns == "emc_auth" && name != "" {
				fq := ns + "_" + name
				names[fq] = true
				if strings.HasPrefix(sel.Sel.Name, "NewHistogram") {
					histograms[fq] = true
				}
			}
			return true
		})
	}
	if len(names) == 0 {
		t.Fatal("parsed zero emc_auth metrics from package source — the scan itself is broken")
	}
	for _, n := range PoolMetricNames() {
		names[n] = true
	}
	return names, histograms
}

// checkEmcToken validates one emc_auth_* token against the known set.
// Histogram children (_bucket/_sum/_count) are legal only on names the source
// declared as histograms.
func checkEmcToken(tok string, names, histograms map[string]bool, where string) error {
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		if strings.HasSuffix(tok, suf) {
			base := strings.TrimSuffix(tok, suf)
			if !histograms[base] {
				return fmt.Errorf("%s: %s uses %s on %s, which is not a histogram in metrics.go", where, tok, suf, base)
			}
			return nil
		}
	}
	if !names[tok] {
		return fmt.Errorf("%s: %s is not a metric exported by this server", where, tok)
	}
	return nil
}

// unquoteScalar strips a YAML single- or double-quoted scalar; plain scalars
// pass through. Trailing YAML comments on the same line are left alone — the
// token regex only pulls metric-name-shaped substrings, which comments do not
// produce.
func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
	}
	return s
}

// exprEntry is one expr: line and the alert it belongs to ("" when the file
// has no alert context, e.g. a config file or a line above the first alert).
type exprEntry struct {
	file  string
	alert string
	expr  string
}

// scanExprs returns every expr: line in a YAML file with the name of the
// alert rule that precedes it.
func scanExprs(t *testing.T, path string) []exprEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []exprEntry
	var current string
	for _, line := range strings.Split(string(data), "\n") {
		if m := alertNameRe.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if m := exprLineRe.FindStringSubmatch(line); m != nil {
			out = append(out, exprEntry{file: filepath.Base(path), alert: current, expr: unquoteScalar(m[1])})
		}
	}
	return out
}

// dashboardExprs walks a dashboard JSON document and returns every
// targets[].expr in every panel, descending into nested panels arrays (row
// panels) recursively.
func dashboardExprs(node any, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		if t, ok := v["targets"]; ok {
			if arr, ok := t.([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						if e, ok := m["expr"].(string); ok {
							*out = append(*out, e)
						}
					}
				}
			}
		}
		if p, ok := v["panels"]; ok {
			dashboardExprs(p, out)
		}
	case []any:
		for _, item := range v {
			dashboardExprs(item, out)
		}
	}
}

func dashboardFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(repoRel("infra", "grafana", "dashboards", "*.json"))
	if err != nil {
		t.Fatalf("glob dashboards: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no dashboard JSON files found — provisioning would load nothing")
	}
	return files
}

func readDashboard(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var dash map[string]any
	if err := json.Unmarshal(data, &dash); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return dash
}

// why: #217 — dashboards, alert rules and promtool test fixtures all name
// metric series by hand. Renaming or deleting a metric in metrics.go would
// leave every reference green-looking but permanently "No data" / silently
// absent — the same declared-but-dead failure the codebase already hit with
// rate_limit_hits_total. This test fails when any reference names a series
// the server does not export, or a _bucket/_sum/_count suffix lands on a
// non-histogram.
func TestObservability_RuleMetricsExist(t *testing.T) {
	names, histograms := knownMetricNames(t)

	// --- Source 1: expr: lines in infra/prometheus/*.yml ---
	promFiles, err := filepath.Glob(repoRel("infra", "prometheus", "*.yml"))
	if err != nil {
		t.Fatalf("glob prometheus yml: %v", err)
	}
	if len(promFiles) == 0 {
		t.Fatal("no prometheus rule/config files found")
	}
	exprTokens := 0
	var hostCPUNodes []string
	for _, path := range promFiles {
		for _, e := range scanExprs(t, path) {
			toks := emcTokenRe.FindAllString(e.expr, -1)
			exprTokens += len(toks)
			for _, tok := range toks {
				if err := checkEmcToken(tok, names, histograms, e.file+" expr ("+e.alert+")"); err != nil {
					t.Error(err)
				}
			}
			for _, tok := range nodeTokenRe.FindAllString(e.expr, -1) {
				if e.alert != "HostCPUHigh" {
					t.Errorf("%s expr (%s): node_* token %s may only appear inside HostCPUHigh", e.file, e.alert, tok)
				} else {
					hostCPUNodes = append(hostCPUNodes, tok)
				}
			}
		}
	}
	if exprTokens == 0 {
		t.Error("scanned prometheus expr lines found zero emc_auth_* tokens — an empty scan must fail, not pass")
	}
	if len(hostCPUNodes) == 0 {
		t.Error("HostCPUHigh expr contains no node_* series — the alert would never fire")
	}

	// --- Source 2: series: lines in infra/prometheus/tests/*.yml ---
	testFiles, err := filepath.Glob(repoRel("infra", "prometheus", "tests", "*.yml"))
	if err != nil {
		t.Fatalf("glob prometheus tests: %v", err)
	}
	if len(testFiles) == 0 {
		t.Fatal("no promtool test files found")
	}
	allowedNodes := map[string]bool{}
	for _, tok := range dedupe(hostCPUNodes) {
		allowedNodes[tok] = true
	}
	seriesTokens := 0
	for _, path := range testFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			m := seriesLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			series := unquoteScalar(m[1])
			toks := emcTokenRe.FindAllString(series, -1)
			seriesTokens += len(toks)
			for _, tok := range toks {
				if err := checkEmcToken(tok, names, histograms, filepath.Base(path)+" series"); err != nil {
					t.Error(err)
				}
			}
			for _, tok := range nodeTokenRe.FindAllString(series, -1) {
				if !allowedNodes[tok] {
					t.Errorf("%s series: node_* series %s is not one HostCPUHigh evaluates", filepath.Base(path), tok)
				}
			}
		}
	}
	if seriesTokens == 0 {
		t.Error("scanned test series lines found zero emc_auth_* tokens — an empty scan must fail, not pass")
	}

	// --- Source 3: targets[].expr in every dashboard panel ---
	dashTokens := 0
	for _, path := range dashboardFiles(t) {
		var exprs []string
		dashboardExprs(readDashboard(t, path), &exprs)
		for _, expr := range exprs {
			toks := emcTokenRe.FindAllString(expr, -1)
			dashTokens += len(toks)
			for _, tok := range toks {
				if err := checkEmcToken(tok, names, histograms, filepath.Base(path)+" panel"); err != nil {
					t.Error(err)
				}
			}
			for _, tok := range nodeTokenRe.FindAllString(expr, -1) {
				t.Errorf("%s panel: node_* token %s may only appear inside the HostCPUHigh alert", filepath.Base(path), tok)
			}
		}
	}
	if dashTokens == 0 {
		t.Error("scanned dashboard exprs found zero emc_auth_* tokens — an empty scan must fail, not pass")
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// why: #217 — a dashboard that parses but has a duplicate uid, no panels, a
// datasource reference pointing at a uid that does not exist, or a hidden
// `or vector(0)` would either fail to provision or, worse, read as live data
// while hiding a dead scrape. The datasource uid is read out of the
// provisioning file rather than hard-coded so the two files stay locked
// together.
func TestObservability_DashboardsValid(t *testing.T) {
	dsData, err := os.ReadFile(repoRel("infra", "grafana", "provisioning", "datasources", "prometheus.yml"))
	if err != nil {
		t.Fatalf("read datasource provisioning: %v", err)
	}
	dsUID := ""
	for _, line := range strings.Split(string(dsData), "\n") {
		if m := uidLineRe.FindStringSubmatch(line); m != nil {
			dsUID = m[1]
			break
		}
	}
	if dsUID == "" {
		t.Fatal("no uid found in datasources/prometheus.yml — dashboards cannot reference it")
	}

	seenUIDs := map[string]string{}
	for _, path := range dashboardFiles(t) {
		base := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", base, err)
		}
		if strings.Contains(string(data), "vector(0)") {
			t.Errorf("%s contains vector(0) — it hides 'never scraped' behind a fake zero", base)
		}
		var dash map[string]any
		if err := json.Unmarshal(data, &dash); err != nil {
			t.Fatalf("parse %s: %v", base, err)
		}
		uid, _ := dash["uid"].(string)
		if uid == "" {
			t.Errorf("%s has no uid", base)
		}
		if other, dup := seenUIDs[uid]; dup {
			t.Errorf("dashboard uid %q used by both %s and %s", uid, other, base)
		}
		seenUIDs[uid] = base
		if title, _ := dash["title"].(string); title == "" {
			t.Errorf("%s has empty title", base)
		}

		var panels []any
		findPanels(dash, &panels)
		if len(panels) == 0 {
			t.Errorf("%s has no panels", base)
			continue
		}
		hasUpStat := false
		for _, p := range panels {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if err := checkDatasource(pm["datasource"], dsUID); err != nil {
				t.Errorf("%s panel %v: %v", base, pm["title"], err)
			}
			targets, _ := pm["targets"].([]any)
			for _, tgt := range targets {
				tm, ok := tgt.(map[string]any)
				if !ok {
					continue
				}
				if err := checkDatasource(tm["datasource"], dsUID); err != nil {
					t.Errorf("%s panel %v target: %v", base, pm["title"], err)
				}
				if pm["type"] == "stat" {
					if expr, _ := tm["expr"].(string); strings.Contains(expr, `up{job="emc-auth-server"}`) {
						hasUpStat = true
					}
				}
			}
		}
		if !hasUpStat {
			t.Errorf("%s has no stat panel on up{job=\"emc-auth-server\"} — 'scrape down' is indistinguishable from 'no events'", base)
		}
	}
}

// findPanels collects every panel object in a dashboard, descending into
// nested panels arrays (row panels) recursively.
func findPanels(node any, out *[]any) {
	switch v := node.(type) {
	case map[string]any:
		if p, ok := v["panels"].([]any); ok {
			*out = append(*out, p...)
			for _, item := range p {
				findPanels(item, out)
			}
		}
	}
}

func checkDatasource(ds any, wantUID string) error {
	m, ok := ds.(map[string]any)
	if !ok {
		return fmt.Errorf("datasource missing")
	}
	if typ, _ := m["type"].(string); typ != "prometheus" {
		return fmt.Errorf("datasource type %v, want prometheus", m["type"])
	}
	if uid, _ := m["uid"].(string); uid != wantUID {
		return fmt.Errorf("datasource uid %q, want %q", uid, wantUID)
	}
	return nil
}

// why: #217 — the issue lists the signals each dashboard must surface. A
// panel silently dropped (or an expr typo'd onto a nonexistent metric) would
// leave the acceptance 'every dashboard shows live data' unmeetable for that
// signal. Each required name must appear in at least one panel expr.
func TestObservability_DashboardCoverage(t *testing.T) {
	required := []string{
		"emc_auth_http_request_duration_seconds",
		"emc_auth_http_requests_in_flight",
		"emc_auth_password_hash_duration_seconds",
		"emc_auth_password_hash_in_flight",
		"emc_auth_rate_limit_hits_total",
		"emc_auth_rate_limit_fail_open_total",
		"emc_auth_audit_queue_depth",
		"emc_auth_audit_events_dropped_total",
		"emc_auth_audit_flush_duration_seconds",
		"emc_auth_tokens_issued_total",
		"emc_auth_tokens_revoked_total",
		"emc_auth_mfa_challenges_total",
		"emc_auth_session_revocations_total",
		"emc_auth_db_pool_acquired_conns",
	}
	var exprs []string
	for _, path := range dashboardFiles(t) {
		dashboardExprs(readDashboard(t, path), &exprs)
	}
	if len(exprs) == 0 {
		t.Fatal("no dashboard exprs found")
	}
	for _, name := range required {
		found := false
		for _, e := range exprs {
			if strings.Contains(e, name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required metric %s appears in no dashboard expr", name)
		}
	}
}

// why: #217 — the receiver URL must come from a file/env, never a literal in
// the repo: a committed webhook URL is a committed secret (Slack incoming
// webhooks and PagerDuty keys are bearer credentials). url_file is also the
// only thing the mounted *.secret / webhook_url.local mechanism can feed.
func TestObservability_AlertmanagerHasNoInlineURL(t *testing.T) {
	data, err := os.ReadFile(repoRel("infra", "alertmanager", "alertmanager.yml"))
	if err != nil {
		t.Fatalf("read alertmanager.yml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "url_file") {
		t.Error("alertmanager.yml has no url_file — the receiver URL must come from a file, not a literal")
	}
	urlKey := regexp.MustCompile(`(?m)^\s*-?\s*url\s*:`)
	if urlKey.MatchString(content) {
		t.Error("alertmanager.yml contains an inline url: key — use url_file only")
	}
	for _, bad := range []string{"http://", "https://", "hooks.slack.com"} {
		if strings.Contains(content, bad) {
			t.Errorf("alertmanager.yml contains %q — no URL literal belongs in the repo", bad)
		}
	}
	local, err := os.ReadFile(repoRel("infra", "alertmanager", "webhook_url.local"))
	if err != nil {
		t.Fatalf("read webhook_url.local: %v", err)
	}
	if string(local) != "http://alert-sink:8080/" {
		t.Errorf("webhook_url.local = %q, want exactly %q (no trailing newline)", string(local), "http://alert-sink:8080/")
	}
}
