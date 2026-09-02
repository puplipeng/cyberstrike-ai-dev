package githubleak

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type secretPattern struct {
	name       string
	re         *regexp.Regexp
	confidence string
	severity   string
}

type assignmentSpec struct {
	kind       string
	confidence string
	severity   string
	minLength  int
	minEntropy float64
	minClasses int
}

var strongSecretPatterns = []secretPattern{
	{name: "github_token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), confidence: "likely", severity: "critical"},
	{name: "github_fine_grained_token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,255}\b`), confidence: "likely", severity: "critical"},
	{name: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), confidence: "likely", severity: "high"},
	{name: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,250}\b`), confidence: "likely", severity: "high"},
	{name: "stripe_live_secret", re: regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,255}\b`), confidence: "likely", severity: "critical"},
	{name: "sendgrid_api_key", re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), confidence: "likely", severity: "critical"},
	{name: "npm_token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{24,255}\b`), confidence: "likely", severity: "high"},
	{name: "private_key", re: regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[ \t]*(?:\r?\n|\\n|\\r\\n)(?:[A-Za-z0-9+/=]|\\/|\\r|\\n|\r|\n){32,}?(?:\r?\n|\\n|\\r\\n)-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`), confidence: "likely", severity: "critical"},
}

var credentialAssignmentStartRE = regexp.MustCompile(`(?m)(?:^|[ \t{};,]|\[)(?:"([A-Za-z][A-Za-z0-9_.-]{1,127})"|'([A-Za-z][A-Za-z0-9_.-]{1,127})'|` + "`" + `([A-Za-z][A-Za-z0-9_.-]{1,127})` + "`" + `|([A-Za-z][A-Za-z0-9_.-]{1,127}))[ \t]*[:=][ \t]*`)

var (
	apiKeySpec             = assignmentSpec{kind: "api_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	llmAPIKeySpec          = assignmentSpec{kind: "llm_api_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	llmAccessKeySpec       = assignmentSpec{kind: "llm_access_key", confidence: "suspected", severity: "medium", minLength: 12, minEntropy: 2.8, minClasses: 2}
	llmSecretKeySpec       = assignmentSpec{kind: "llm_secret_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	cloudAccessKeyIDSpec   = assignmentSpec{kind: "cloud_access_key_id", confidence: "suspected", severity: "medium", minLength: 12, minEntropy: 2.8, minClasses: 2}
	cloudSecretKeySpec     = assignmentSpec{kind: "cloud_secret_access_key", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	oauthClientSecretSpec  = assignmentSpec{kind: "oauth_client_secret", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	webhookSecretSpec      = assignmentSpec{kind: "webhook_signing_secret", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	authTokenSpec          = assignmentSpec{kind: "auth_token", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	strictBareTokenSpec    = assignmentSpec{kind: "auth_token", confidence: "suspected", severity: "high", minLength: 24, minEntropy: 3.5, minClasses: 2}
	bearerTokenSpec        = assignmentSpec{kind: "bearer_token", confidence: "suspected", severity: "high", minLength: 16, minEntropy: 3.0, minClasses: 2}
	genericNamedSecretSpec = assignmentSpec{kind: "generic_secret_assignment", confidence: "suspected", severity: "medium", minLength: 16, minEntropy: 3.2, minClasses: 2}
	passwordSecretSpec     = assignmentSpec{kind: "generic_secret_assignment", confidence: "suspected", severity: "medium", minLength: 16, minEntropy: 3.3, minClasses: 3}
)

type Detector struct{ hmacKey []byte }

func NewDetector(settings Settings) (*Detector, error) {
	normalized, err := settings.Normalize()
	if err != nil {
		return nil, err
	}
	key := []byte(normalized.FingerprintKey)
	if len(normalized.FingerprintKey) >= 4 && strings.EqualFold(normalized.FingerprintKey[:4], "hex:") {
		encoded := normalized.FingerprintKey[4:]
		if len(encoded) != sha256.Size*2 {
			return nil, errors.New("hex fingerprint key must contain exactly 64 hexadecimal characters")
		}
		key, err = hex.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("hex fingerprint key is invalid")
		}
	}
	if len(key) == 0 && normalized.Token != "" {
		digest := sha256.Sum256([]byte("CyberStrikeAI/githubleak/fingerprint/v1\x00" + normalized.Token))
		key = digest[:]
	}
	if len(key) < 16 {
		return nil, errors.New("a GitHub token or fingerprint key is required for HMAC fingerprints")
	}
	return &Detector{hmacKey: append([]byte(nil), key...)}, nil
}

// Detect returns only sanitized candidates. Raw matches remain local to this
// function and are never included in the returned value.
func (d *Detector) Detect(keyword string, item SearchItem) []Candidate {
	if d == nil || len(d.hmacKey) == 0 {
		return nil
	}
	results := make([]Candidate, 0)
	seen := map[string]struct{}{}
	line := lineNumberFromURL(item.HTMLURL)
	for _, fragment := range item.Fragments {
		if !utf8.ValidString(fragment) || len(fragment) > 64<<10 {
			continue
		}
		strongRanges := make([][2]int, 0)
		for _, pattern := range strongSecretPatterns {
			for _, loc := range pattern.re.FindAllStringIndex(fragment, -1) {
				if len(loc) != 2 || loc[0] < 0 || loc[1] <= loc[0] {
					continue
				}
				raw := fragment[loc[0]:loc[1]]
				if !credibleStrongSecret(raw) {
					continue
				}
				strongRanges = append(strongRanges, [2]int{loc[0], loc[1]})
				fingerprint := d.fingerprint(pattern.name, raw)
				seenKey := pattern.name + ":" + strconv.Itoa(line) + ":" + fingerprint
				if _, ok := seen[seenKey]; ok {
					continue
				}
				seen[seenKey] = struct{}{}
				results = append(results, sanitizedCandidate(keyword, item, pattern.name, pattern.confidence, pattern.severity, fingerprint, fragment, loc[0], loc[1]))
			}
		}
		for _, assignment := range credentialAssignments(fragment) {
			if overlapsAny(assignment.valueStart, assignment.valueEnd, strongRanges) {
				continue
			}
			// Client IDs and cloud/LLM access-key IDs are public identifiers. They
			// may anchor a paired search, but never become findings on their own.
			if isPublicCredentialIdentifierKey(assignment.key) {
				continue
			}
			spec := assignmentSpec{}
			if assignment.bearer {
				spec = bearerTokenSpec
			} else {
				var ok bool
				spec, ok = classifyCredentialKey(assignment.key)
				if !ok {
					continue
				}
			}
			raw := fragment[assignment.valueStart:assignment.valueEnd]
			if !credibleAssignedValue(raw, spec) {
				continue
			}
			fingerprint := d.fingerprint(spec.kind, raw)
			seenKey := spec.kind + ":" + strconv.Itoa(line) + ":" + fingerprint
			if _, ok := seen[seenKey]; ok {
				continue
			}
			seen[seenKey] = struct{}{}
			results = append(results, sanitizedCandidate(keyword, item, spec.kind, spec.confidence, spec.severity, fingerprint, fragment, assignment.valueStart, assignment.valueEnd))
		}
	}
	return results
}

func overlapsAny(start, end int, ranges [][2]int) bool {
	for _, candidate := range ranges {
		if start < candidate[1] && end > candidate[0] {
			return true
		}
	}
	return false
}

func (d *Detector) fingerprint(kind, raw string) string {
	mac := hmac.New(sha256.New, d.hmacKey)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func sanitizedCandidate(keyword string, item SearchItem, kind, confidence, severity, fingerprint, fragment string, start, end int) Candidate {
	return Candidate{
		Keyword:       keyword,
		Repository:    item.Repository,
		Path:          item.Path,
		BlobSHA:       item.BlobSHA,
		Line:          lineNumberFromURL(item.HTMLURL),
		SecretType:    kind,
		Confidence:    confidence,
		Severity:      severity,
		Fingerprint:   fingerprint,
		MaskedExcerpt: maskedExcerpt(fragment, start, end, kind),
		HTMLURL:       item.HTMLURL,
	}
}

func lineNumberFromURL(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil || len(u.Fragment) < 2 || u.Fragment[0] != 'L' {
		return 0
	}
	line, err := strconv.Atoi(u.Fragment[1:])
	if err != nil || line < 1 || line > 100000000 {
		return 0
	}
	return line
}

func maskedExcerpt(_ string, _, _ int, kind string) string {
	// Search fragments can contain unrelated credentials on the same line. A
	// fixed marker is the only fail-closed excerpt: no fragment bytes ever cross
	// the detector boundary into a Candidate or persistent finding.
	return "<redacted:" + kind + ">"
}

// maskOtherSecrets is used only for defensive sanitization of internal error
// text. Candidate excerpts never call it; they are fixed markers above.
func maskOtherSecrets(value string) string {
	for _, pattern := range strongSecretPatterns {
		value = pattern.re.ReplaceAllString(value, "<redacted:"+pattern.name+">")
	}
	assignments := credentialAssignmentsForMasking(value)
	for i := len(assignments) - 1; i >= 0; i-- {
		assignment := assignments[i]
		spec, ok := classifyCredentialKey(assignment.key)
		if assignment.bearer {
			spec, ok = bearerTokenSpec, true
		} else if isClientIdentifierKey(assignment.key) {
			spec, ok = assignmentSpec{kind: "oauth_client_id"}, true
		}
		if ok {
			value = value[:assignment.valueStart] + "<redacted:" + spec.kind + ">" + value[assignment.valueEnd:]
		}
	}
	return value
}

type credentialAssignment struct {
	key                  string
	valueStart, valueEnd int
	bearer               bool
}

func credentialAssignments(fragment string) []credentialAssignment {
	matches := credentialAssignmentStartRE.FindAllStringSubmatchIndex(fragment, -1)
	result := make([]credentialAssignment, 0, len(matches))
	for _, match := range matches {
		key := credentialAssignmentKey(fragment, match)
		if key == "" {
			continue
		}
		start, end, ok := 0, 0, false
		bearer := isAuthorizationKey(key)
		if bearer {
			start, end, ok = parseBearerToken(fragment, match[1])
		} else {
			start, end, ok = parseAssignmentValue(fragment, match[1])
		}
		if ok {
			assignment := credentialAssignment{key: key, valueStart: start, valueEnd: end, bearer: bearer}
			if len(result) > 0 && assignment.valueStart < result[len(result)-1].valueEnd {
				if assignment.valueEnd > result[len(result)-1].valueEnd {
					result[len(result)-1].valueEnd = assignment.valueEnd
				}
				continue
			}
			result = append(result, assignment)
		}
	}
	return result
}

// credentialAssignmentsForMasking is deliberately more greedy than the
// detector parser. Once an error names a sensitive field, masking an adjacent
// delimiter or message suffix is safer than retaining part of an unquoted or
// unterminated credential in logs.
func credentialAssignmentsForMasking(fragment string) []credentialAssignment {
	matches := credentialAssignmentStartRE.FindAllStringSubmatchIndex(fragment, -1)
	result := make([]credentialAssignment, 0, len(matches))
	for _, match := range matches {
		key := credentialAssignmentKey(fragment, match)
		if key == "" {
			continue
		}
		bearer := isAuthorizationKey(key)
		start, end, ok := 0, 0, false
		if bearer {
			start, end, ok = parseBearerTokenForMasking(fragment, match[1])
		} else {
			start, end, ok = parseAssignmentValueForMasking(fragment, match[1])
		}
		if ok {
			assignment := credentialAssignment{key: key, valueStart: start, valueEnd: end, bearer: bearer}
			if len(result) > 0 && assignment.valueStart < result[len(result)-1].valueEnd {
				if assignment.valueEnd > result[len(result)-1].valueEnd {
					result[len(result)-1].valueEnd = assignment.valueEnd
				}
				continue
			}
			result = append(result, assignment)
		}
	}
	return result
}

func credentialAssignmentKey(fragment string, match []int) string {
	if len(match) < 10 {
		return ""
	}
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] > match[i] {
			return fragment[match[i]:match[i+1]]
		}
	}
	return ""
}

func parseAssignmentValue(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if quote := fragment[start]; quote == '\'' || quote == '"' || quote == '`' {
		valueStart, escaped := start+1, false
		for i := valueStart; i < len(fragment) && i-valueStart <= 512; i++ {
			if fragment[i] == '\r' || fragment[i] == '\n' {
				return 0, 0, false
			}
			if escaped {
				escaped = false
				continue
			}
			if fragment[i] == '\\' {
				escaped = true
				continue
			}
			if fragment[i] == quote {
				return valueStart, i, i > valueStart
			}
		}
		return 0, 0, false
	}
	end := start
	for end < len(fragment) && end-start <= 512 {
		switch fragment[end] {
		case ' ', '\t', '\r', '\n', ',', ';', '}', ']':
			return start, end, end > start
		}
		end++
	}
	return start, end, end > start && end-start <= 512
}

func parseAssignmentValueForMasking(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if quote := fragment[start]; quote == '\'' || quote == '"' || quote == '`' {
		valueStart, escaped := start+1, false
		limit := len(fragment)
		for i := valueStart; i < limit; i++ {
			if fragment[i] == '\r' || fragment[i] == '\n' {
				return valueStart, i, i > valueStart
			}
			if escaped {
				escaped = false
				continue
			}
			if fragment[i] == '\\' {
				escaped = true
				continue
			}
			if fragment[i] == quote {
				return valueStart, i, i > valueStart
			}
		}
		return valueStart, limit, limit > valueStart
	}
	end := start
	limit := len(fragment)
	for end < limit {
		switch fragment[end] {
		case ' ', '\t', '\r', '\n':
			return start, end, end > start
		}
		end++
	}
	return start, end, end > start
}

func parseBearerToken(fragment string, start int) (int, int, bool) {
	contentStart, contentEnd := start, start
	if start < len(fragment) && (fragment[start] == '\'' || fragment[start] == '"' || fragment[start] == '`') {
		var ok bool
		contentStart, contentEnd, ok = parseAssignmentValue(fragment, start)
		if !ok {
			return 0, 0, false
		}
	} else {
		for contentEnd < len(fragment) && contentEnd-start <= 520 {
			if strings.ContainsRune("\r\n,;}]", rune(fragment[contentEnd])) {
				break
			}
			contentEnd++
		}
	}
	content := fragment[contentStart:contentEnd]
	if len(content) < 7 || !strings.EqualFold(content[:6], "bearer") || (content[6] != ' ' && content[6] != '\t') {
		return 0, 0, false
	}
	offset := 6
	for offset < len(content) && (content[offset] == ' ' || content[offset] == '\t') {
		offset++
	}
	tokenStart := contentStart + offset
	tokenEnd := tokenStart
	for tokenEnd < contentEnd && fragment[tokenEnd] != ' ' && fragment[tokenEnd] != '\t' {
		tokenEnd++
	}
	return tokenStart, tokenEnd, tokenEnd > tokenStart
}

func parseBearerTokenForMasking(fragment string, start int) (int, int, bool) {
	if start < 0 || start >= len(fragment) {
		return 0, 0, false
	}
	if fragment[start] == '\'' || fragment[start] == '"' || fragment[start] == '`' {
		contentStart, contentEnd, ok := parseAssignmentValueForMasking(fragment, start)
		if !ok {
			return 0, 0, false
		}
		content := fragment[contentStart:contentEnd]
		if len(content) < 7 || !strings.EqualFold(content[:6], "bearer") || (content[6] != ' ' && content[6] != '\t') {
			return 0, 0, false
		}
		offset := 6
		for offset < len(content) && (content[offset] == ' ' || content[offset] == '\t') {
			offset++
		}
		return contentStart + offset, contentEnd, contentEnd > contentStart+offset
	}
	if len(fragment)-start < 7 || !strings.EqualFold(fragment[start:start+6], "bearer") ||
		(fragment[start+6] != ' ' && fragment[start+6] != '\t') {
		return 0, 0, false
	}
	tokenStart := start + 6
	for tokenStart < len(fragment) && (fragment[tokenStart] == ' ' || fragment[tokenStart] == '\t') {
		tokenStart++
	}
	tokenEnd := tokenStart
	limit := len(fragment)
	for tokenEnd < limit {
		switch fragment[tokenEnd] {
		case ' ', '\t', '\r', '\n':
			return tokenStart, tokenEnd, tokenEnd > tokenStart
		}
		tokenEnd++
	}
	return tokenStart, tokenEnd, tokenEnd > tokenStart
}

func isAuthorizationKey(key string) bool {
	id := compactCredentialKey(key)
	return id == "authorization" || id == "proxyauthorization"
}

func isClientIdentifierKey(key string) bool {
	id := compactCredentialKey(key)
	return id == "appid" || id == "oauthappid" || hasCredentialSuffix(id, "clientid", "oauthclientid")
}

func isPublicCredentialIdentifierKey(key string) bool {
	id := compactCredentialKey(key)
	if isClientIdentifierKey(key) {
		return true
	}
	return id == "accesskey" || hasCredentialSuffix(id,
		"accesskeyid", "qianfanak", "huaweicloudak", "tencentcloudsecretid",
		"twilioapikey", "twilioapisid", "twilioaccountsid",
	)
}

func classifyCredentialKey(key string) (assignmentSpec, bool) {
	id := compactCredentialKey(key)
	if id == "" {
		return assignmentSpec{}, false
	}
	if hasCredentialSuffix(id,
		"openaiapikey", "anthropicapikey", "deepseekapikey", "dashscopeapikey", "arkapikey",
		"moonshotapikey", "zhipuaiapikey", "zhipuapikey", "glmapikey", "qwenapikey",
		"qianfanapikey", "geminiapikey", "googleaiapikey", "mistralapikey", "groqapikey",
		"cohereapikey", "togetherapikey", "perplexityapikey", "openrouterapikey",
		"siliconflowapikey", "minimaxapikey", "doubaoapikey", "azureopenaiapikey",
		"googleapikey", "googlegenaiapikey", "googlegenerativeaiapikey", "xaiapikey", "fireworksapikey",
		"voyageapikey", "pineconeapikey", "weaviateapikey", "langsmithapikey", "langchainapikey",
		"heliconeapikey", "cloudflareaiapikey", "ollamaapikey", "bedrockapikey",
	) {
		return llmAPIKeySpec, true
	}
	if hasCredentialSuffix(id,
		"openaikey", "claudeapikey", "azureopenaikey",
		"replicateapitoken", "huggingfacehubapitoken", "hftoken",
	) {
		return llmAPIKeySpec, true
	}
	if hasCredentialSuffix(id, "qianfanak") {
		return llmAccessKeySpec, true
	}
	if hasCredentialSuffix(id, "qianfansk") {
		return llmSecretKeySpec, true
	}
	if hasCredentialSuffix(id, "clientsecret", "consumersecret") {
		return oauthClientSecretSpec, true
	}
	if hasCredentialSuffix(id, "webhooksecret", "signingsecret") {
		return webhookSecretSpec, true
	}
	if hasCredentialSuffix(id, "secretaccesskey", "accesskeysecret") ||
		hasCredentialSuffix(id, "awssecretkey", "aliyunsecretkey", "alibabacloudsecretkey", "tencentcloudsecretkey", "huaweicloudsk") {
		return cloudSecretKeySpec, true
	}
	if id == "accesskey" || hasCredentialSuffix(id, "accesskeyid") || hasCredentialSuffix(id, "huaweicloudak") ||
		(strings.Contains(id, "tencentcloud") && hasCredentialSuffix(id, "secretid")) {
		return cloudAccessKeyIDSpec, true
	}
	if id == "apikey" || id == "xapikey" || hasCredentialSuffix(id, "apikey") {
		return apiKeySpec, true
	}
	if id == "bearertoken" || hasCredentialSuffix(id, "bearertoken") {
		return bearerTokenSpec, true
	}
	if id == "token" {
		return strictBareTokenSpec, true
	}
	if id == "idtoken" || id == "oidcidtoken" || hasCredentialSuffix(id,
		"accesstoken", "authtoken", "apitoken", "servicetoken", "bottoken",
		"webhooktoken", "refreshtoken", "oauthtoken", "sessiontoken", "sastoken",
		"githubtoken", "gitlabtoken", "ghtoken", "privatetoken", "deploytoken",
		"registrytoken", "personalaccesstoken",
	) {
		return authTokenSpec, true
	}
	if id == "secret" || hasCredentialSuffix(id,
		"apisecret", "apisecretkey", "appsecret", "sharedsecret", "encryptionsecret",
		"jwtsecret", "sessionsecret", "cookiesecret", "secretkey", "signingkey",
		"encryptionkey", "masterkey", "privatekey", "serviceaccountkey",
	) {
		return genericNamedSecretSpec, true
	}
	if id == "password" || id == "passwd" || hasCredentialSuffix(id,
		"dbpassword", "databasepassword", "redispassword", "cachepassword", "smtppassword",
		"adminpassword", "servicepassword", "userpassword",
	) {
		return passwordSecretSpec, true
	}
	return assignmentSpec{}, false
}

func compactCredentialKey(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasCredentialSuffix(value string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if value == suffix || strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func credibleAssignedValue(value string, spec assignmentSpec) bool {
	value = strings.TrimSpace(value)
	if len(value) < spec.minLength || len(value) > 512 || isPlaceholderCredentialValue(value) {
		return false
	}
	if credentialValueClasses(value) < spec.minClasses {
		return false
	}
	return shannonEntropy(value) >= spec.minEntropy
}

func isPlaceholderCredentialValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "arn:") {
		return true
	}
	for _, prefix := range []string{
		"$", "%", "process.env.", "process.env[", "os.getenv", "os.environ", "system.getenv",
		"environment.getenvironmentvariable", "env(", "env.", "config.", "settings.",
		"viper.get", "vault://", "vault.", "secret://", "var.", "local.", "module.",
		"secrets.", "secrets[", "@microsoft.keyvault(",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, exact := range []string{
		"none", "null", "undefined", "secret", "password", "passwd", "token", "apikey", "api_key",
		"development", "production", "default", "true", "false",
	} {
		if lower == exact {
			return true
		}
	}
	for _, marker := range []string{
		"example", "sample", "dummy", "changeme", "change-me", "change_me", "replace",
		"placeholder", "<redacted", "redacted:", "your_", "your-", "your.", "not-a-real",
		"not_real", "fake-key", "fake_key", "test-key", "test_key", "test-token", "test_token",
		"sk-test", "${", "{{", "localhost", "xxxxx",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	runes := []rune(value)
	if len(runes) > 0 {
		allSame := true
		for _, r := range runes[1:] {
			if r != runes[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

func credibleStrongSecret(value string) bool {
	return !isPlaceholderCredentialValue(value) && credentialValueClasses(value) >= 2 && shannonEntropy(value) >= 2.8
}

func credentialValueClasses(value string) int {
	classes := 0
	for _, predicate := range []func(rune) bool{
		unicode.IsLower,
		unicode.IsUpper,
		unicode.IsDigit,
		func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) },
	} {
		for _, r := range value {
			if predicate(r) {
				classes++
				break
			}
		}
	}
	return classes
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
