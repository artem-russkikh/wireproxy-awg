package wireproxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// jsEscapeRule
// ---------------------------------------------------------------------------

func TestJsEscapeRuleNoSpecialChars(t *testing.T) {
	cases := []string{
		"||example.com",
		"|http://example.com/path",
		"||google.com",
		".suffix.com",
	}
	for _, s := range cases {
		// strings with no " or \ must come through unchanged
		if got := jsEscapeRule(s); got != s {
			t.Errorf("jsEscapeRule(%q) = %q, want %q (no change expected)", s, got, s)
		}
	}
}

func TestJsEscapeRuleQuotes(t *testing.T) {
	got := jsEscapeRule(`domain-with-"quotes".com`)
	want := `domain-with-\"quotes\".com`
	if got != want {
		t.Errorf("jsEscapeRule = %q, want %q", got, want)
	}
}

func TestJsEscapeRuleBackslash(t *testing.T) {
	got := jsEscapeRule(`back\slash`)
	want := `back\\slash`
	if got != want {
		t.Errorf("jsEscapeRule = %q, want %q", got, want)
	}
}

func TestJsEscapeRuleMixed(t *testing.T) {
	got := jsEscapeRule(`a\b"c`)
	want := `a\\b\"c`
	if got != want {
		t.Errorf("jsEscapeRule = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// parseGFWList — plain text input
// ---------------------------------------------------------------------------

func TestParseGFWListPlainText(t *testing.T) {
	input := `! comment line
[AutoProxy 1.0]

||google.com
||twitter.com
@@||googleapis.com
.example.com
|http://blocked.site/path
`
	rules, exceptions := parseGFWList([]byte(input))

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d: %v", len(rules), rules)
	}
	if len(exceptions) != 1 {
		t.Fatalf("expected 1 exception, got %d: %v", len(exceptions), exceptions)
	}
	if rules[0] != "||google.com" {
		t.Errorf("rules[0] = %q, want %q", rules[0], "||google.com")
	}
	if rules[1] != "||twitter.com" {
		t.Errorf("rules[1] = %q, want %q", rules[1], "||twitter.com")
	}
	if exceptions[0] != "||googleapis.com" {
		t.Errorf("exceptions[0] = %q, want %q", exceptions[0], "||googleapis.com")
	}
}

func TestParseGFWListSkipsCommentsAndHeaders(t *testing.T) {
	input := `! comment 1
! comment 2
[AutoProxy 1.0]
||real-rule.com
! trailing comment
`
	rules, exceptions := parseGFWList([]byte(input))

	if len(rules) != 1 || rules[0] != "||real-rule.com" {
		t.Errorf("expected rules=[||real-rule.com], got %v", rules)
	}
	if len(exceptions) != 0 {
		t.Errorf("expected no exceptions, got %v", exceptions)
	}
}

func TestParseGFWListEmptyInput(t *testing.T) {
	rules, exceptions := parseGFWList([]byte(""))
	if len(rules) != 0 || len(exceptions) != 0 {
		t.Errorf("expected empty lists, got rules=%v exceptions=%v", rules, exceptions)
	}
}

// ---------------------------------------------------------------------------
// parseGFWList — base64-encoded input
// ---------------------------------------------------------------------------

func TestParseGFWListBase64Encoded(t *testing.T) {
	content := `! GFWList
[AutoProxy 1.0]
||youtube.com
@@||ytimg.com
`
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	rules, exceptions := parseGFWList([]byte(encoded))

	if len(rules) != 1 || rules[0] != "||youtube.com" {
		t.Errorf("expected rules=[||youtube.com], got %v", rules)
	}
	if len(exceptions) != 1 || exceptions[0] != "||ytimg.com" {
		t.Errorf("expected exceptions=[||ytimg.com], got %v", exceptions)
	}
}

func TestParseGFWListBase64WithWhitespace(t *testing.T) {
	content := "||test.com\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	// Simulate trailing newline that real-world gfwlist.txt files have
	rules, _ := parseGFWList([]byte(encoded + "\n"))
	if len(rules) != 1 || rules[0] != "||test.com" {
		t.Errorf("unexpected rules: %v", rules)
	}
}

func TestParseGFWListEscapesJSMetaChars(t *testing.T) {
	input := `||domain-with-"quotes".com`
	rules, _ := parseGFWList([]byte(input))
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if !strings.Contains(rules[0], `\"`) {
		t.Errorf("expected escaped double-quotes in rule, got %q", rules[0])
	}
}

// ---------------------------------------------------------------------------
// generatePAC
// ---------------------------------------------------------------------------

func TestGeneratePACContainsAllParts(t *testing.T) {
	rules := []string{"||google.com", "||twitter.com"}
	exceptions := []string{"||googleapis.com"}
	proxy := "SOCKS5 127.0.0.1:1080; DIRECT"

	pac, err := generatePAC(proxy, rules, exceptions)
	if err != nil {
		t.Fatalf("generatePAC error: %s", err)
	}

	for _, want := range []string{
		`var proxy = "SOCKS5 127.0.0.1:1080; DIRECT"`,
		`"||google.com"`,
		`"||twitter.com"`,
		`"||googleapis.com"`,
		"function FindProxyForURL",
		"function matchRule",
	} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC output missing %q", want)
		}
	}
}

func TestGeneratePACEmptyLists(t *testing.T) {
	pac, err := generatePAC("DIRECT", nil, nil)
	if err != nil {
		t.Fatalf("generatePAC error: %s", err)
	}
	if !strings.Contains(pac, "function FindProxyForURL") {
		t.Error("PAC missing FindProxyForURL")
	}
	// Empty arrays are valid JS
	if !strings.Contains(pac, "var rules = [") {
		t.Error("PAC missing rules declaration")
	}
}

func TestGeneratePACExceptionsBeforeRules(t *testing.T) {
	rules := []string{"||blocked.com"}
	exceptions := []string{"||allowed.com"}

	pac, err := generatePAC("SOCKS5 127.0.0.1:1080", rules, exceptions)
	if err != nil {
		t.Fatal(err)
	}
	// exceptions array should appear before rules array in the file
	excIdx := strings.Index(pac, `"||allowed.com"`)
	ruleIdx := strings.Index(pac, `"||blocked.com"`)
	if excIdx == -1 || ruleIdx == -1 {
		t.Fatal("missing expected rule or exception in PAC")
	}
	if excIdx > ruleIdx {
		t.Error("exception should appear before rule in PAC output")
	}
}

// ---------------------------------------------------------------------------
// loadGFWList — local file
// ---------------------------------------------------------------------------

func TestLoadGFWListLocalFile(t *testing.T) {
	content := "||local-test.com\n"
	f, err := os.CreateTemp(t.TempDir(), "gfwlist*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(content)
	f.Close()

	data, err := loadGFWList(f.Name(), "", false)
	if err != nil {
		t.Fatalf("loadGFWList error: %s", err)
	}
	if string(data) != content {
		t.Errorf("got %q, want %q", data, content)
	}
}

func TestLoadGFWListLocalFileIgnoresCacheFile(t *testing.T) {
	dir := t.TempDir()
	localFile := filepath.Join(dir, "gfwlist.txt")
	cacheFile := filepath.Join(dir, "cache.txt")

	_ = os.WriteFile(localFile, []byte("||local.com\n"), 0o644)
	_ = os.WriteFile(cacheFile, []byte("||cached.com\n"), 0o644)

	// Even though cacheFile exists, for a local source it must be ignored
	data, err := loadGFWList(localFile, cacheFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "||local.com\n" {
		t.Errorf("expected local file content, got %q", data)
	}
}

// ---------------------------------------------------------------------------
// loadGFWList — disk cache logic (URL source, no real network)
// ---------------------------------------------------------------------------

func TestLoadGFWListUsesCacheWhenPresent(t *testing.T) {
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "cache.txt")
	cachedContent := "||cached-rule.com\n"
	_ = os.WriteFile(cacheFile, []byte(cachedContent), 0o644)

	// forceRefresh=false with an unreachable URL: should use cache, not network
	data, err := loadGFWList("https://nonexistent.invalid/gfwlist.txt", cacheFile, false)
	if err != nil {
		t.Fatalf("loadGFWList error: %s", err)
	}
	if string(data) != cachedContent {
		t.Errorf("expected cached content %q, got %q", cachedContent, data)
	}
}

func TestLoadGFWListForceRefreshFallsBackToStaleCache(t *testing.T) {
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "cache.txt")
	_ = os.WriteFile(cacheFile, []byte("||stale.com\n"), 0o644)

	// forceRefresh=true with unreachable URL — no stale-fallback because
	// forceRefresh skips the cache-read path and only reads cache on download failure.
	// Here the download will fail AND there is a stale cache → stale fallback used.
	data, err := loadGFWList("https://nonexistent.invalid/gfwlist.txt", cacheFile, true)
	if err != nil {
		t.Fatalf("expected stale-cache fallback, got error: %s", err)
	}
	if string(data) != "||stale.com\n" {
		t.Errorf("expected stale cache content, got %q", data)
	}
}

func TestLoadGFWListNoCacheNoURL(t *testing.T) {
	// URL source, no cacheFile, unreachable URL → must return an error
	_, err := loadGFWList("https://nonexistent.invalid/gfwlist.txt", "", false)
	if err == nil {
		t.Fatal("expected error when URL unreachable and no cache")
	}
}

// ---------------------------------------------------------------------------
// loadExtraRules
// ---------------------------------------------------------------------------

func TestLoadExtraRules(t *testing.T) {
	content := "||custom1.com\n||custom2.com\n@@||allowed.com\n"
	f, err := os.CreateTemp(t.TempDir(), "extra*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(content)
	f.Close()

	rules, exceptions, err := loadExtraRules(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 extra rules, got %d: %v", len(rules), rules)
	}
	if len(exceptions) != 1 {
		t.Errorf("expected 1 extra exception, got %d: %v", len(exceptions), exceptions)
	}
}

func TestLoadExtraRulesMissingFile(t *testing.T) {
	_, _, err := loadExtraRules("/nonexistent/path/extra.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// buildPAC — extra rules merged in-memory
// ---------------------------------------------------------------------------

func TestBuildPACMergesExtraRules(t *testing.T) {
	dir := t.TempDir()

	// Base GFWList (local file, plain text)
	baseFile := filepath.Join(dir, "base.txt")
	_ = os.WriteFile(baseFile, []byte("||base-rule.com\n"), 0o644)

	// Extra rules file
	extraFile := filepath.Join(dir, "extra.txt")
	_ = os.WriteFile(extraFile, []byte("||chatgpt.com\n||openai.com\n@@||cdn.openai.com\n"), 0o644)

	cfg := &PACConfig{
		BindAddress: "127.0.0.1:8080",
		GFWList:     baseFile,
		ExtraRules:  extraFile,
		Proxy:       "SOCKS5 127.0.0.1:1080; DIRECT",
	}

	pac, err := buildPAC(cfg, false)
	if err != nil {
		t.Fatalf("buildPAC error: %s", err)
	}

	for _, want := range []string{"||base-rule.com", "||chatgpt.com", "||openai.com", "||cdn.openai.com"} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC missing %q", want)
		}
	}
}

func TestBuildPACExtraRulesNotWrittenToCache(t *testing.T) {
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "cache.txt")
	baseFile := filepath.Join(dir, "base.txt")
	extraFile := filepath.Join(dir, "extra.txt")

	_ = os.WriteFile(baseFile, []byte("||base.com\n"), 0o644)
	_ = os.WriteFile(extraFile, []byte("||extra-only.com\n"), 0o644)
	// Simulate a pre-existing cache (same content as base so loadGFWList uses it)
	_ = os.WriteFile(cacheFile, []byte("||base.com\n"), 0o644)

	cfg := &PACConfig{
		BindAddress: "127.0.0.1:8080",
		GFWList:     "https://nonexistent.invalid/gfwlist.txt", // URL → will use cache
		CacheFile:   cacheFile,
		ExtraRules:  extraFile,
		Proxy:       "DIRECT",
	}

	_, err := buildPAC(cfg, false)
	if err != nil {
		t.Fatalf("buildPAC error: %s", err)
	}

	// Cache file must NOT contain extra rules
	cacheData, _ := os.ReadFile(cacheFile)
	if strings.Contains(string(cacheData), "extra-only") {
		t.Error("extra rules must not be written to the cache file")
	}
}

func TestBuildPACExtraRulesTakePriority(t *testing.T) {
	dir := t.TempDir()
	baseFile := filepath.Join(dir, "base.txt")
	extraFile := filepath.Join(dir, "extra.txt")
	_ = os.WriteFile(baseFile, []byte("||base.com\n"), 0o644)
	_ = os.WriteFile(extraFile, []byte("||priority.com\n"), 0o644)

	cfg := &PACConfig{
		BindAddress: "127.0.0.1:8080",
		GFWList:     baseFile,
		ExtraRules:  extraFile,
		Proxy:       "DIRECT",
	}

	pac, err := buildPAC(cfg, false)
	if err != nil {
		t.Fatal(err)
	}

	// Extra rule should appear before the base rule in the rules array
	extraIdx := strings.Index(pac, `"||priority.com"`)
	baseIdx := strings.Index(pac, `"||base.com"`)
	if extraIdx == -1 || baseIdx == -1 {
		t.Fatal("missing expected rules in PAC")
	}
	if extraIdx > baseIdx {
		t.Error("extra rules should appear before base rules (higher priority)")
	}
}
