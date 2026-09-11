"""Conservative Java-like source heuristics, not a Java parser or a proof of exploitability."""
import re

VERSION = 'apk-code-2.0'
RULES = {
    'command-input': ('外部输入进入系统命令', 'high', 'CWE-78', '避免执行拼接命令；固定程序和参数白名单，限制外部输入。'),
    'sql-input': ('外部输入进入 SQL 文本', 'high', 'CWE-89', '使用占位符与绑定参数；不要把外部输入拼接到 SQL 文本。'),
    'webview-script-input': ('外部输入进入 WebView 脚本执行', 'high', 'CWE-79', '不要将外部输入作为 JavaScript 执行；限制可信页面与桥接权限。'),
    'dynamic-input': ('外部输入控制动态代码加载路径', 'high', 'CWE-94', '只加载可信私有目录中的代码，并在加载前验证签名和完整性。'),
    'file-input': ('外部输入控制文件写入路径', 'high', 'CWE-22', '规范化路径并校验它仍位于允许的根目录；拒绝目录穿越与不可信绝对路径。'),
    'ssl-proceed': ('证书错误回调继续连接', 'high', 'CWE-295', '在证书错误回调中取消连接，修复服务端证书；不要调用 proceed。'),
    'trust-all': ('服务端证书校验实现为空', 'high', 'CWE-295', '使用系统 TrustManager 验证证书链，不使用空实现。'),
    'hostname-all': ('主机名校验无条件通过', 'high', 'CWE-297', '使用系统主机名校验并验证证书与访问域名一致。'),
}
REFERENCES = [
    'https://developer.android.com/privacy-and-security/risks/unsafe-hostname',
    'https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges',
    'https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading',
    'https://developer.android.com/privacy-and-security/security-ssl',
]

def mask(source, strings=False):
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    def replace(m):
        s = m.group()
        if not strings and not s.startswith(('/', '//')):
            return s
        return ''.join('\n' if c == '\n' else ' ' for c in s)
    return re.sub(pattern, replace, source)

SOURCE = re.compile(r'\b(?:getIntent|getStringExtra|getCharSequenceExtra|getDataString|getQueryParameter|getPathParameter|getText)\s*\(|\.\s*(?:getData|readLine)\s*\(')
SINKS = [
    ('command-input', re.compile(r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bnew\s+(?:java\.lang\.)?ProcessBuilder\s*\(')),
    ('sql-input', re.compile(r'\.\s*(?:rawQuery|execSQL)\s*\(')),
    ('webview-script-input', re.compile(r'\.\s*evaluateJavascript\s*\(')),
    ('dynamic-input', re.compile(r'\bnew\s+(?:dalvik\.system\.)?(?:DexClassLoader|PathClassLoader)\s*\(')),
    ('file-input', re.compile(r'\bnew\s+(?:java\.io\.)?(?:FileOutputStream|FileWriter)\s*\(')),
]

def first_argument(code, start):
    depth = 0
    for i in range(start, len(code)):
        if code[i] in '([{': depth += 1
        elif code[i] in ')]}':
            if depth == 0: return code[start:i]
            depth -= 1
        elif code[i] == ',' and depth == 0: return code[start:i]
    return ''

def analyze_method(source, method='', class_context=''):
    """Local lexical propagation only. Branches, call dispatch and sanitizers need human review."""
    code = mask(source, True)
    findings, seen = [], set()
    def emit(rule, at, origin=None):
        line = source.count('\n', 0, at) + 1
        if (rule, line) in seen: return
        seen.add((rule, line))
        title, severity, cwe, fix = RULES[rule]
        lines = source.splitlines()
        start, end = max(0, line - 4), min(len(lines), line + 3)
        findings.append(dict(rule=rule, title=title, severity=severity, cwe=cwe,
            status='needs_review', confidence='heuristic', line=line,
            evidence='\n'.join(f'{i+1}: {lines[i]}' for i in range(start, end))[:2500],
            source_evidence=origin or '', recommendation=fix,
            conditions='核查调用可达性、输入控制权、权限与前置校验。局部词法传播不等于已证明的污点路径。'))
    # Each call receives ONE method, preventing propagation between unrelated methods.
    taint = {}
    def origin(expr):
        if SOURCE.search(expr): return expr.strip()[:500]
        for token in re.findall(r'\b[A-Za-z_$][\w$]*\b', expr):
            if token in taint: return taint[token]
        return None
    offset = 0
    for statement in code.split(';'):
        for rule, pattern in SINKS:
            for m in pattern.finditer(statement):
                value = first_argument(statement, m.end())
                src = origin(value)
                if src: emit(rule, offset + m.start(), src)
        assignment = re.search(r'\b([A-Za-z_$][\w$]*)\s*(\+?=)(?!=)\s*([\s\S]*)$', statement)
        if assignment:
            name, op, expr = assignment.groups()
            src = origin(expr) or (taint.get(name) if op == '+=' else None)
            if src: taint[name] = src
            else: taint.pop(name, None)
        offset += len(statement) + 1
    body = code[code.find('{')+1:code.rfind('}')] if '{' in code else code
    if method == 'onReceivedSslError' and re.search(r'\bSslErrorHandler\b', code):
        for m in re.finditer(r'\.\s*proceed\s*\(', code): emit('ssl-proceed', m.start())
    if method == 'checkServerTrusted' and re.search(r'\bX509TrustManager\b', class_context) and re.fullmatch(r'\s*(?:return\s*;)?\s*', body):
        emit('trust-all', max(0, code.find('{')))
    if method == 'verify' and re.search(r'\bHostnameVerifier\b', class_context) and re.fullmatch(r'\s*return\s+(?:true|1)\s*;\s*', body):
        emit('hostname-all', max(0, code.find('return')))
    return findings
