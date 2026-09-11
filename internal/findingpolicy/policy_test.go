package findingpolicy

import (
	"strings"
	"testing"
)

func TestExcludedCategories(t *testing.T) {
	for _, title := range []string{
		"CORS misconfiguration", "跨域资源共享漏洞", "Access-Control-Allow-Origin wildcard",
		"TLS 1.0 Protocol Detection", "TLSv1.1 supported", "SSLv3 enabled", "tls-1.0-enabled",
		"废弃的 TLS 协议", "SSL 弱加密套件", "Weak cipher suites",
		"SSH端口暴露", "开放端口 22", "Open ports", "exposed services", "管理后台可访问",
		"内网IP地址泄露", "绝对路径泄漏", "后端API地址泄露 + OSS存储桶确认", "Nginx版本信息泄露",
		"Port 22 is open", "后端 API 地址泄露", "端口暴露可能导致未授权访问", "内网IP泄露但未证实SSRF",
		"子域名枚举", "version disclosure", "internal IP disclosure", "banner disclosure",
	} {
		t.Run(title, func(t *testing.T) {
			if got := Check(title, "信息泄露"); got == nil {
				t.Fatal("excluded finding was accepted")
			}
		})
	}
	if Check("严重漏洞", "CORS") == nil {
		t.Fatal("type must also enforce policy")
	}
}

func TestIndependentFindingsAndIncidentalTermsRemainAllowed(t *testing.T) {
	for _, input := range [][2]string{
		{"未授权访问 Redis 并读取敏感数据，端口暴露", "未授权访问"},
		{"接口泄露用户数据", "敏感数据泄露"},
		{"配置文件私钥泄露", "信息泄露"},
		{"SQL注入（响应含 CORS 头）", "SQL注入"},
		{"https://cors.example.com/path 参数注入", "SQL注入"},
		{"TLS 1.3 implementation memory corruption", "memory corruption"},
		{"SQL Injection", "SQL Injection"},
		{"Stored XSS", "XSS"},
		{"XSS（响应含 CORS 头）", "XSS"},
		{"TLS 1.0 implementation buffer overflow", "memory corruption"},
	} {
		if got := Check(input[0], input[1]); got != nil {
			t.Errorf("independent finding %q rejected: %v", input[0], got)
		}
	}
	if Check("读取敏感数据", "CORS") == nil {
		t.Fatal("explicitly excluded type must not be overridden by impact wording")
	}
}

func TestPromptPreservesCustomInstructionAndDoesNotDuplicate(t *testing.T) {
	got := AppendPrompt("custom instruction")
	if !strings.HasPrefix(got, "custom instruction") || !strings.Contains(got, Prompt) || AppendPrompt(got) != got {
		t.Fatal("prompt policy must be present exactly once without replacing custom instructions")
	}
}

func TestPolicyMovesAfterRoleAdditions(t *testing.T) {
	got := AppendPrompt(AppendPrompt("base") + "\ncustom role addition")
	if !strings.HasSuffix(got, Prompt) || strings.Count(got, Prompt) != 1 || !strings.Contains(got, "custom role addition") {
		t.Fatal("policy must follow custom role additions once")
	}
}
