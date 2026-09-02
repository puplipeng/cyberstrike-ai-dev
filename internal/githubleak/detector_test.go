package githubleak

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func testDetector(t *testing.T, key, token string) *Detector {
	t.Helper()
	detector, err := NewDetector(Settings{
		Token:          token,
		FingerprintKey: key,
		Keywords:       []string{"storage-service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func syntheticGitHubToken(seed string) string {
	return "ghp_" + seed + "7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r0S1t3"
}

func candidateOfType(candidates []Candidate, kind string) (Candidate, bool) {
	for _, candidate := range candidates {
		if candidate.SecretType == kind {
			return candidate, true
		}
	}
	return Candidate{}, false
}

func TestDetectorStrongRulesReturnOnlySanitizedEvidence(t *testing.T) {
	key := "unit-test-fingerprint-key-32-bytes"
	detector := testDetector(t, key, "")
	tests := []struct {
		kind string
		raw  string
	}{
		{kind: "github_token", raw: syntheticGitHubToken("A")},
		{kind: "stripe_live_secret", raw: "sk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"},
		{kind: "google_api_key", raw: "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			item := SearchItem{
				Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
				HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
				Fragments: []string{"value = \"" + tc.raw + "\""},
			}
			candidates := detector.Detect("storage-service", item)
			candidate, ok := candidateOfType(candidates, tc.kind)
			if !ok {
				t.Fatal("strong detector did not return the expected type")
			}
			serialized, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), tc.raw) || strings.Contains(candidate.MaskedExcerpt, tc.raw) || candidate.Fingerprint == tc.raw {
				t.Fatal("raw credential survived detector sanitization")
			}
			if len(candidate.Fingerprint) != sha256.Size*2 {
				t.Fatalf("fingerprint length = %d", len(candidate.Fingerprint))
			}
			if _, err := hex.DecodeString(candidate.Fingerprint); err != nil {
				t.Fatal("fingerprint is not hexadecimal")
			}
		})
	}
}

func TestDetectorPrivateKeyRequiresCompleteFooterAndSupportsEscapedEncryptedKeys(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7V2m9R4x8Nc6W"
	tests := []struct {
		name     string
		fragment string
		want     int
	}{
		{name: "complete pem", fragment: "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----", want: 1},
		{name: "encrypted pem", fragment: "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\n" + body + "\n-----END ENCRYPTED PRIVATE KEY-----", want: 1},
		{name: "json escaped rsa pem", fragment: `{"key":"-----BEGIN RSA ` + `PRIVATE KEY-----\n` + body + `\n-----END RSA PRIVATE KEY-----"}`, want: 1},
		{name: "missing footer", fragment: "-----BEGIN " + "PRIVATE KEY-----\n" + body, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Detect("private-key", SearchItem{
				Repository: "owner/repo", Path: "key.txt", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/key.txt", Fragments: []string{tc.fragment},
			})
			if len(got) != tc.want {
				t.Fatalf("private key candidates = %+v, want %d", got, tc.want)
			}
			if tc.want == 1 && got[0].SecretType != "private_key" {
				t.Fatalf("private key type = %q", got[0].SecretType)
			}
		})
	}
}

func TestDetectorExcerptNeverRetainsAnyFragmentValue(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	primary := syntheticGitHubToken("B")
	secondary := "111111111111"
	candidates := detector.Detect("vendor.example", SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{"AWS_ACCESS_KEY_ID=" + primary + " backup_password=" + secondary},
	})
	if len(candidates) == 0 {
		t.Fatal("GitHub token fixture was not detected")
	}
	for _, candidate := range candidates {
		serialized, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(serialized), primary) || strings.Contains(string(serialized), secondary) {
			t.Fatalf("candidate retained fragment data: %s", serialized)
		}
		if want := "<redacted:" + candidate.SecretType + ">"; candidate.MaskedExcerpt != want {
			t.Fatalf("masked excerpt = %q, want fixed marker %q", candidate.MaskedExcerpt, want)
		}
	}
}

func TestDetectorSuppressesGenericDuplicateForStrongAssignment(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	raw := syntheticGitHubToken("D")
	candidates := detector.Detect("storage-service", SearchItem{
		Repository: "owner/repo", Path: "secret.env", BlobSHA: strings.Repeat("b", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/secret.env",
		Fragments: []string{"token = \"" + raw + "\""},
	})
	if len(candidates) != 1 || candidates[0].SecretType != "github_token" {
		t.Fatalf("strong assignment produced %d candidates; want one strong candidate", len(candidates))
	}
	if strings.Contains(candidates[0].MaskedExcerpt, raw) {
		t.Fatal("strong assignment excerpt contains the raw credential")
	}
}

func TestDetectorOAuthClientSecretUsesKeyedHMAC(t *testing.T) {
	key := "unit-test-fingerprint-key-32-bytes"
	raw := "Ab9/7Kp2_Qx4-Zm8+Rt6"
	detector := testDetector(t, key, "")
	candidates := detector.Detect("vendor.example", SearchItem{
		Repository: "owner/repo", Path: "settings.ini", BlobSHA: strings.Repeat("c", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/settings.ini",
		Fragments: []string{"client_secret = \"" + raw + "\""},
	})
	if len(candidates) != 1 || candidates[0].SecretType != "oauth_client_secret" {
		t.Fatalf("generic assignment candidates = %d", len(candidates))
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("oauth_client_secret"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	want := hex.EncodeToString(mac.Sum(nil))
	if candidates[0].Fingerprint != want {
		t.Fatal("generic assignment did not use the configured keyed HMAC")
	}
	if strings.Contains(candidates[0].MaskedExcerpt, raw) {
		t.Fatal("generic assignment excerpt contains the raw credential")
	}
}

func TestDetectorAssignmentSyntaxesAndClientIdentifiersStaySanitized(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	tests := []struct {
		name       string
		fragment   string
		raw        string
		kind       string
		confidence string
		severity   string
	}{
		{name: "json client secret", fragment: `{"clientSecret": "Ab9/7Kp2_Qx4-Zm8+Rt6"}`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", kind: "oauth_client_secret", confidence: "suspected", severity: "high"},
		{name: "yaml secret access key", fragment: `secretAccessKey: Ab9/7Kp2_Qx4-Zm8+Rt6`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", kind: "cloud_secret_access_key", confidence: "suspected", severity: "high"},
		{name: "env client secret", fragment: `CLIENT_SECRET=Ab9/7Kp2_Qx4-Zm8+Rt6`, raw: "Ab9/7Kp2_Qx4-Zm8+Rt6", kind: "oauth_client_secret", confidence: "suspected", severity: "high"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			item := SearchItem{
				Repository: "owner/repo", Path: "config.txt", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.txt", Fragments: []string{tc.fragment},
			}
			candidate, ok := candidateOfType(detector.Detect(`"clientid" AND "vendor.example" in:file`, item), tc.kind)
			if !ok {
				t.Fatalf("%s assignment was not detected", tc.kind)
			}
			if candidate.Confidence != tc.confidence || candidate.Severity != tc.severity {
				t.Fatalf("classification = %s/%s", candidate.Confidence, candidate.Severity)
			}
			serialized, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(serialized), tc.raw) || strings.Contains(candidate.MaskedExcerpt, tc.raw) {
				t.Fatalf("raw assignment value survived sanitization: %s", serialized)
			}
		})
	}
}

func TestDetectorCredentialFieldFamilies(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	tests := []struct {
		name, fragment, raw, kind string
	}{
		{name: "snake api key", fragment: `api_key="ak_live_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "ak_live_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "api_key"},
		{name: "camel api key", fragment: `{"apiKey":"ak_prod_N8z4Kp2_Qx7Lm9R5Vc3W"}`, raw: "ak_prod_N8z4Kp2_Qx7Lm9R5Vc3W", kind: "api_key"},
		{name: "compact api key", fragment: `apikey: ak_prod_R5v8Nc3_Wp7Kq2Lm9Xz4`, raw: "ak_prod_R5v8Nc3_Wp7Kq2Lm9Xz4", kind: "api_key"},
		{name: "header api key", fragment: `x-api-key: "ak_prod_Z4m7Qp2_Ln9Vc5Rx8Kw3"`, raw: "ak_prod_Z4m7Qp2_Ln9Vc5Rx8Kw3", kind: "api_key"},
		{name: "cloud secret", fragment: `AWS_SECRET_ACCESS_KEY="p9/Qx4+Lm7_Nc2-Rt8=Vk5Za3"`, raw: "p9/Qx4+Lm7_Nc2-Rt8=Vk5Za3", kind: "cloud_secret_access_key"},
		{name: "oauth client secret", fragment: `oauth_client_secret="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "cs_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "oauth_client_secret"},
		{name: "webhook secret", fragment: `SLACK_SIGNING_SECRET="wh_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "wh_Q7v2Lm9!R4x8#Nc6$Wp3%Za", kind: "webhook_signing_secret"},
		{name: "access token", fragment: `ACCESS_TOKEN="tok_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "tok_Q7v2Lm9!R4x8#Nc6$Wp3%Za", kind: "auth_token"},
		{name: "bearer variable", fragment: `BEARER_TOKEN="bt_Q7v2Lm9!R4x8#Nc6$Wp3%Za"`, raw: "bt_Q7v2Lm9!R4x8#Nc6$Wp3%Za", kind: "bearer_token"},
		{name: "bearer header", fragment: `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.Q7v2Lm9R4x8N.c6Wp3Za5Kd2F`, raw: "eyJhbGciOiJIUzI1NiJ9.Q7v2Lm9R4x8N.c6Wp3Za5Kd2F", kind: "bearer_token"},
		{name: "qianfan sk", fragment: `QIANFAN_SK="QFs_Q7v2Lm9R4x8Nc6Wp3Za"`, raw: "QFs_Q7v2Lm9R4x8Nc6Wp3Za", kind: "llm_secret_key"},
		{name: "oauth consumer secret", fragment: `CONSUMER_SECRET="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "cs_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "oauth_client_secret"},
		{name: "jwt secret", fragment: `JWT_SECRET="jwt_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "jwt_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "generic_secret_assignment"},
		{name: "generic secret key", fragment: `SECRET_KEY="sec_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "sec_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "generic_secret_assignment"},
		{name: "github named token", fragment: `GITHUB_TOKEN="tok_Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "tok_Q7v2Lm9_R4x8Nc6Wp3Za", kind: "auth_token"},
		{name: "redis password", fragment: `REDIS_PASSWORD="pw!Q7v2Lm9_R4x8Nc6Wp3Za"`, raw: "pw!Q7v2Lm9_R4x8Nc6Wp3Za", kind: "generic_secret_assignment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := detector.Detect("field-family", SearchItem{
				Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("a", 40),
				HTMLURL: "https://github.com/owner/repo/blob/main/config.env", Fragments: []string{tc.fragment},
			})
			candidate, ok := candidateOfType(candidates, tc.kind)
			if !ok || len(candidates) != 1 {
				t.Fatalf("candidates = %+v, want one %s", candidates, tc.kind)
			}
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), tc.raw) || candidate.MaskedExcerpt != "<redacted:"+tc.kind+">" {
				t.Fatalf("candidate was not fully sanitized: %s", data)
			}
		})
	}

	for _, key := range []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY",
		"ARK_API_KEY", "MOONSHOT_API_KEY", "ZHIPUAI_API_KEY", "GEMINI_API_KEY",
		"GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY", "XAI_API_KEY", "FIREWORKS_API_KEY",
		"AZURE_OPENAI_KEY", "REPLICATE_API_TOKEN", "HF_TOKEN",
	} {
		t.Run(key, func(t *testing.T) {
			fragment := key + `="llm_Q7v2Lm9_R4x8Nc6Wp3Za"`
			candidates := detector.Detect("llm", SearchItem{Repository: "owner/repo", Path: "llm.env", BlobSHA: strings.Repeat("b", 40), HTMLURL: "https://github.com/owner/repo/blob/main/llm.env", Fragments: []string{fragment}})
			if len(candidates) != 1 || candidates[0].SecretType != "llm_api_key" {
				t.Fatalf("%s candidates = %+v", key, candidates)
			}
		})
	}
}

func TestDetectorRejectsMetadataPlaceholdersAndClientIDOnly(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	negatives := []string{
		`token password api_key`,
		`token_endpoint=https://auth.example.com/token`,
		`password_policy=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`secret_name=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`api_key_ref=Q7v2Lm9_R4x8Nc6Wp3Za`,
		`OPENAI_API_KEY=sk-your-api-key-here`,
		`OPENAI_API_KEY=${OPENAI_API_KEY}`,
		`OPENAI_API_KEY=$OPENAI_API_KEY`,
		`OPENAI_API_KEY=%OPENAI_API_KEY%`,
		`OPENAI_API_KEY=os.environ["OPENAI_API_KEY"]`,
		`OPENAI_API_KEY=process.env["OPENAI_API_KEY"]`,
		`OPENAI_API_KEY=Environment.GetEnvironmentVariable("OPENAI_API_KEY")`,
		`OPENAI_API_KEY=settings.OPENAI_API_KEY`,
		`client_secret=process.env.OAUTH_CLIENT_SECRET`,
		`password=hunter2`,
		`token=ordinarytokenvalue`,
		`api_key=1234567890123456`,
		"client_secret:\nordinary_value=Q7v2Lm9_R4x8Nc6Wp3Za",
		`client_secret="unterminated_Q7v2Lm9_R4x8Nc6Wp3Za`,
		`client_id=mt_8F3kL7pQ2xV9nR5c`,
		`AWS_ACCESS_KEY_ID=AKIA` + `IOSFODNN7EXAMPLE`,
		`AWS_ACCESS_KEY_ID=AKIA` + `Q1W2E3R4T5Y6U7I8`,
		`QIANFAN_AK=QF7mP2xN9cR4vK8z`,
		`TWILIO_API_KEY=SK` + `0123456789abcdef0123456789abcdef`,
		`SK` + `0123456789abcdef0123456789abcdef`,
		`token=ghp_` + `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	for _, fragment := range negatives {
		if got := detector.Detect("negative", SearchItem{Repository: "owner/repo", Path: "fixture.txt", BlobSHA: strings.Repeat("c", 40), HTMLURL: "https://github.com/owner/repo/blob/main/fixture.txt", Fragments: []string{fragment}}); len(got) != 0 {
			t.Fatalf("negative fragment %q produced candidates: %+v", fragment, got)
		}
	}

	fragment := `client_id=mt_8F3kL7pQ2xV9nR5c client_secret="cs_Q7v2Lm9_R4x8Nc6Wp3Za"`
	got := detector.Detect("oauth", SearchItem{Repository: "owner/repo", Path: "oauth.env", BlobSHA: strings.Repeat("d", 40), HTMLURL: "https://github.com/owner/repo/blob/main/oauth.env", Fragments: []string{fragment}})
	if len(got) != 1 || got[0].SecretType != "oauth_client_secret" {
		t.Fatalf("client id + secret produced %+v; want only oauth_client_secret", got)
	}

	fragment = `AWS_ACCESS_KEY_ID=AKIA` + `Q1W2E3R4T5Y6U7I8 AWS_SECRET_ACCESS_KEY="p9/Qx4+Lm7_Nc2-Rt8=Vk5Za3"`
	got = detector.Detect("aws-pair", SearchItem{Repository: "owner/repo", Path: "aws.env", BlobSHA: strings.Repeat("e", 40), HTMLURL: "https://github.com/owner/repo/blob/main/aws.env", Fragments: []string{fragment}})
	if len(got) != 1 || got[0].SecretType != "cloud_secret_access_key" {
		t.Fatalf("AWS identifier + secret produced %+v; want only cloud_secret_access_key", got)
	}
}

func TestMaskOtherSecretsRedactsCompletePunctuatedValues(t *testing.T) {
	raw := "P!ssw0rd?Long#2026&More"
	got := maskOtherSecrets(`provider failed password="` + raw + `"`)
	if strings.Contains(got, raw) || strings.Contains(got, "2026&More") || !strings.Contains(got, "<redacted:generic_secret_assignment>") {
		t.Fatalf("safe error masking retained credential bytes: %q", got)
	}
	unquoted := "Ab9/7Kp2,Qx4;Zm8+Rt6&More"
	got = maskOtherSecrets("provider failed api_key=" + unquoted + " retry denied")
	if strings.Contains(got, unquoted) || strings.Contains(got, "Qx4;Zm8") || !strings.Contains(got, "<redacted:api_key>") {
		t.Fatalf("safe error masking retained an unquoted credential tail: %q", got)
	}
	got = maskOtherSecrets(`provider failed client_secret="Ab9/7Kp2,Qx4;Zm8+Rt6&More`)
	if strings.Contains(got, "Qx4;Zm8") || !strings.Contains(got, "<redacted:oauth_client_secret>") {
		t.Fatalf("safe error masking retained an unterminated credential tail: %q", got)
	}
	first, second := "Ak9/Qx4,Lm7+Nc2", "Cs8/Rt5;Wp3+Za6"
	got = maskOtherSecrets("api_key=" + first + ",client_secret=" + second)
	if strings.Contains(got, first) || strings.Contains(got, second) || !strings.Contains(got, "<redacted:api_key>") {
		t.Fatalf("safe error masking mishandled overlapping assignments: %q", got)
	}
}

func TestDetectorExplicitFingerprintKeyIsStableAcrossGitHubTokenChanges(t *testing.T) {
	raw := syntheticGitHubToken("E")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("d", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{raw},
	}
	first, ok := candidateOfType(testDetector(t, "stable-fingerprint-key-material", "first-unit-token").Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("first detector did not identify the strong token fixture")
	}
	second, ok := candidateOfType(testDetector(t, "stable-fingerprint-key-material", "second-unit-token").Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("second detector did not identify the strong token fixture")
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("GitHub token rotation changed an explicitly keyed fingerprint")
	}
	other, ok := candidateOfType(testDetector(t, "different-fingerprint-key-material", "second-unit-token").Detect("storage-service", item), "github_token")
	if !ok || other.Fingerprint == first.Fingerprint {
		t.Fatal("different HMAC keys did not produce independent fingerprints")
	}
}

func TestDetectorHexFingerprintKeyPreservesLegacyTokenFingerprints(t *testing.T) {
	legacyToken := "legacy-unit-test-pat"
	replacementToken := "rotated-unit-test-pat"
	raw := syntheticGitHubToken("H")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("e", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{raw},
	}
	legacy, ok := candidateOfType(testDetector(t, "", legacyToken).Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("legacy token-derived detector did not identify the fixture")
	}
	digest := sha256.Sum256([]byte("CyberStrikeAI/githubleak/fingerprint/v1\x00" + legacyToken))
	migratedKey := "hex:" + hex.EncodeToString(digest[:])
	migrated, ok := candidateOfType(testDetector(t, migratedKey, replacementToken).Detect("storage-service", item), "github_token")
	if !ok {
		t.Fatal("hex-key detector did not identify the fixture")
	}
	if migrated.Fingerprint != legacy.Fingerprint {
		t.Fatal("hex migration key changed the legacy token-derived fingerprint")
	}
	if _, err := NewDetector(Settings{FingerprintKey: "hex:not-a-64-byte-key", Keywords: []string{"storage-service"}}); err == nil {
		t.Fatal("invalid hex fingerprint key was accepted")
	}
}

func TestDetectorRequiresFingerprintMaterial(t *testing.T) {
	if _, err := NewDetector(Settings{Keywords: []string{"storage-service"}}); err == nil {
		t.Fatal("detector accepted empty token and fingerprint key")
	}
}

func TestDetectorOnlyUsesTrustedGitHubURLLine(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	raw := syntheticGitHubToken("F")
	item := SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("e", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{"first line\n" + raw},
	}
	candidate, ok := candidateOfType(detector.Detect("storage-service", item), "github_token")
	if !ok || candidate.Line != 0 {
		t.Fatalf("fragment-relative line was trusted: %+v", candidate)
	}
	item.HTMLURL += "#L42"
	candidate, ok = candidateOfType(detector.Detect("storage-service", item), "github_token")
	if !ok || candidate.Line != 42 {
		t.Fatalf("trusted URL line was not used: %+v", candidate)
	}
}

func TestDetectorMasksOtherCredentialLikeValueOnExcerptLine(t *testing.T) {
	detector := testDetector(t, "unit-test-fingerprint-key-32-bytes", "")
	primary := syntheticGitHubToken("G")
	secondary := "Z9aB7cD5eF3gH1"
	candidate, ok := candidateOfType(detector.Detect("storage-service", SearchItem{
		Repository: "owner/repo", Path: "token.txt", BlobSHA: strings.Repeat("f", 40),
		HTMLURL:   "https://github.com/owner/repo/blob/main/token.txt",
		Fragments: []string{"token=" + primary + " other=" + secondary},
	}), "github_token")
	if !ok || strings.Contains(candidate.MaskedExcerpt, primary) || strings.Contains(candidate.MaskedExcerpt, secondary) {
		t.Fatalf("masked excerpt retained a credential-like value: %q", candidate.MaskedExcerpt)
	}
}
