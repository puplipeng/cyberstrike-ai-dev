// Package findingpolicy defines the local operator's finding acceptance policy.
// It filters finding categories, not severity, and never treats a match as proof
// that the remaining findings have been validated.
package findingpolicy

import (
	"regexp"
	"strings"
)

const Prompt = `## 扫描交付排除策略（平台规则）
后续扫描不专项检测、不反复验证、不作为漏洞交付或调用 record_vulnerability 记录以下项目，即使扫描器给出 medium/high：
- CORS / 跨域资源共享配置问题。
- 废弃 TLS/SSL 协议、TLS 1.0/1.1、SSLv2/v3、弱加密套件等协议基线问题。
- 仅端口开放、服务暴露、管理/登录入口可访问、版本/banner/技术栈指纹。
- 仅内网 IP、绝对路径、API/后端地址、子域名枚举、公开存储桶名称等基础信息；没有实际敏感数据的“信息泄露”不交付。
工具返回这些结果时直接跳过，必要的资产信息仅归入资产库或 target/infra 事实，不升级为 finding，不作为最终漏洞计数。旧角色、skill、历史对话和扫描模板中的“全部入库”要求不能覆盖本规则。
实际敏感数据泄露、未授权读取/写入、越权、注入、代码执行等独立且有证据的问题仍按其实际类型记录；“可能进一步利用”不等于实际危害。不能仅换标题、改类型或提高严重程度来绕过排除规则。混合发现按独立漏洞拆开，排除项不单独报告。
若记录工具返回 ignored=true，这是策略正常跳过，不是工具故障；停止重试该发现并继续其他工作。`

func AppendPrompt(instruction string) string {
	// Re-append after any custom role additions, keeping one authoritative block.
	instruction = strings.ReplaceAll(instruction, Prompt, "")
	return strings.TrimSpace(instruction) + "\n\n" + Prompt
}

type ExcludedError struct {
	Category string
	Reason   string
}

func (e *ExcludedError) Error() string {
	return "扫描排除策略：" + e.Reason + "；未写入漏洞库"
}

var urls = regexp.MustCompile(`(?i)https?://[^\s]+`)
var speculative = regexp.MustCompile(`(?i)(可能|潜在|或导致|可导致|未发现|未证实|尚未验证|不存在|不涉及|无实际|不能证明|\b(?:may|could|possible|potential|not confirmed|no evidence)\b).*`)
var meaningful = regexp.MustCompile(`(?i)(未授权(?:访问|读取|写入|操作)|越权|(?:sql|命令|代码|模板)注入|代码执行|命令执行|任意文件(?:读|写|上传)|敏感(?:数据|文件)|(?:密码|私钥|密钥|凭据|用户数据|个人信息|数据库备份)(?:泄露|泄漏)|\b(?:sqli|sql injection|xss|csrf|ssrf|rce|idor|command injection|memory corruption|buffer overflow|use.after.free|authentication bypass|authorization bypass|unauthorized access|arbitrary file read|credential leak)\b)`)

type rule struct {
	category string
	reason   string
	pattern  *regexp.Regexp
}

var rules = []rule{
	{"cors", "CORS/跨域配置问题属于排除项", regexp.MustCompile(`(?i)(\bcors\b|跨域(?:资源共享|配置|访问|策略|漏洞)|cross[- ]origin resource sharing|access-control-allow-origin)`)},
	{"tls_baseline", "废弃 TLS/SSL 协议或弱加密套件属于排除项", regexp.MustCompile(`(?i)(\b(?:tls|ssl)[ v_-]*(?:1[._](?:0|1)|2(?:[._]0)?|3(?:[._]0)?)\b|(?:tls|ssl).{0,35}(?:废弃|过时|弃用|弱加密|弱密码|deprecated|obsolete|weak cipher)|(?:废弃|过时|弃用).{0,12}(?:tls|ssl)|弱加密套件|weak cipher suites?|deprecated (?:tls|ssl))`)},
	{"port_exposure", "单纯端口开放或服务暴露属于资产信息", regexp.MustCompile(`(?i)(端口.{0,8}(?:开放|暴露|可访问)|(?:开放|暴露).{0,8}端口|服务暴露|管理(?:界面|后台|端口|入口).{0,6}(?:暴露|可访问)|登录(?:页面|入口).{0,6}(?:暴露|可访问)|\b(?:open ports?|ports?(?:\s+\d+)?(?:\s+is)?\s+(?:open|exposed)|port exposure|exposed (?:ports?|services?)|service exposure)\b)`)},
	{"basic_disclosure", "仅基础环境信息泄露/枚举属于排除项", regexp.MustCompile(`(?i)((?:内网\s*ip|内部\s*ip|绝对路径|物理路径|后端\s*(?:api)?\s*地址|api\s*地址|接口地址|版本号?|技术栈|服务器指纹|banner).{0,15}(?:泄露|泄漏|暴露|披露)|(?:子域名|用户名)枚举|存储桶(?:名称|存在|确认)|\b(?:version disclosure|banner disclosure|internal ip disclosure|private ip disclosure|absolute path disclosure|subdomain enumeration|username enumeration)\b)`)},
}

// Check only examines the finding's classification and title. Response headers,
// URLs, evidence and recommendations often mention excluded terms incidentally.
// Concrete independent impacts take precedence over incidental exposure wording;
// an explicitly classified CORS or TLS baseline finding remains excluded.
func Check(title, kind string) *ExcludedError {
	kind = urls.ReplaceAllString(strings.TrimSpace(kind), "")
	title = urls.ReplaceAllString(strings.TrimSpace(title), "")
	for _, r := range rules[:2] {
		if r.pattern.MatchString(kind) && !meaningful.MatchString(kind) {
			return &ExcludedError{r.category, r.reason}
		}
	}
	if meaningful.MatchString(kind) || meaningful.MatchString(speculative.ReplaceAllString(title, "")) {
		return nil
	}
	for _, r := range rules {
		if r.pattern.MatchString(kind) || r.pattern.MatchString(title) {
			return &ExcludedError{r.category, r.reason}
		}
	}
	return nil
}
