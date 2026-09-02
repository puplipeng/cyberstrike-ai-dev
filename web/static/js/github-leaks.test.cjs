const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const githubLeaks = require('./github-leaks.js');

test('finding HTML escapes untrusted metadata and never reads raw secret fields', () => {
    const rawSecret = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    const finding = {
        id: 'leak"><img src=x onerror=alert(1)>',
        status: 'new',
        rule_name: '<img src=x onerror=alert(1)>',
        keyword: '<script>alert(1)</script>',
        repository: '<svg onload=alert(1)>',
        path: 'config</td><script>bad</script>.env',
        secret_type: '<img src=x>',
        fingerprint: 'sha256:<b>unsafe</b>',
        masked_excerpt: `token=${rawSecret}`,
        html_url: 'https://github.com/example/repo/blob/main/config.env',
        secret: rawSecret,
        raw_secret: rawSecret,
        raw_response: rawSecret,
    };
    const html = githubLeaks.rowHTML(finding) + githubLeaks.detailHTML(finding);
    for (const tag of ['<script', '<img', '<svg', '<b>']) assert.ok(!html.includes(tag), tag);
    assert.ok(!html.includes(rawSecret));
    assert.ok(html.includes('token=••••••••'));
    assert.ok(html.includes('&lt;script&gt;'));
    assert.ok(html.includes('rel="noopener noreferrer"'));
});

test('finding rows prefer the rule name and retain the canonical query', () => {
    const finding = {
        id: 'leak-1',
        status: 'new',
        rule_name: 'example-corp-clientid',
        keyword: '"clientid" AND "vendor.example" in:file',
        repository: 'example/repo',
        path: '.env',
    };
    const row = githubLeaks.rowHTML(finding);
    const detail = githubLeaks.detailHTML(finding);
    assert.match(row, /example-corp-clientid/);
    assert.match(row, /&quot;clientid&quot; AND &quot;vendor\.example&quot; in:file/);
    assert.match(detail, /规则名称/);
    assert.match(detail, /Canonical 查询/);
    assert.match(detail, /example-corp-clientid/);
    assert.match(detail, /&quot;clientid&quot; AND &quot;vendor\.example&quot; in:file/);
});

test('runtime renders every named rule, canonical query and enabled state safely', () => {
    const rawToken = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
    const html = githubLeaks.runtimeRulesHTML({
        rules: [
            { name: 'example-corp-clientid', enabled: true, query: '"clientid" AND "vendor.example" in:file', last_status: 'success' },
            { name: 'idle', enabled: true, query: '"idle" in:file', last_status: 'idle' },
            { name: 'cached', enabled: true, query: '"cached" in:file', last_status: 'not_modified' },
            { name: 'partial', enabled: true, query: '"partial" in:file', last_status: 'partial', incomplete: true, truncated: true },
            { name: '<img src=x onerror=alert(1)>', enabled: false, query: '<script>bad()</script>', last_status: 'error', last_error: `<script>bad()</script> token=${rawToken}` },
        ],
    });
    assert.match(html, /example-corp-clientid/);
    assert.match(html, /已启用/);
    assert.match(html, /已停用/);
    assert.match(html, /成功/);
    assert.match(html, /未变更/);
    assert.match(html, /部分完成/);
    assert.match(html, /结果不完整/);
    assert.match(html, /失败/);
    assert.match(html, /尚未运行/);
    assert.match(html, /结果已截断/);
    assert.match(html, /&quot;clientid&quot; AND &quot;vendor\.example&quot; in:file/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /&lt;script&gt;bad\(\)&lt;\/script&gt;/);
    assert.ok(!html.includes('<img'));
    assert.ok(!html.includes('<script'));
    assert.ok(!html.includes(rawToken));
});

test('the expanded rule inventory is contained in its own bounded scroll region', () => {
    const css = fs.readFileSync(require.resolve('../css/github-leaks.css'), 'utf8');
    assert.match(css, /\.ghl-runtime-rules\{[^}]*max-height:min\(44vh,420px\)/);
    assert.match(css, /\.ghl-runtime-rules\{[^}]*overflow-y:auto/);
    assert.match(css, /\.ghl-runtime-rules\{[^}]*overscroll-behavior:contain/);
});

test('safeGitHubURL only allows credential-free github.com HTTPS links', () => {
    const rejected = [
        'http://github.com/example/repo',
        'https://github.com.evil.example/repo',
        'https://user:password@github.com/example/repo',
        'https://github.com\\@evil.example/repo',
        'https://github.com/example/repo\nfoo',
        '//github.com/example/repo',
        'javascript:alert(1)',
        'data:text/html,bad',
        'file:///C:/secret',
        'https://raw.githubusercontent.com/example/repo/main/file',
        'https://github.com/example/repo/blob/main/file?token=should-not-render',
        'https://github.com/example/repo/blob/main/file#secret-value',
    ];
    for (const value of rejected) assert.equal(githubLeaks.safeGitHubURL(value), '', value);
    assert.equal(
        githubLeaks.safeGitHubURL('https://github.com/example/repo/blob/main/config.env#L10'),
        'https://github.com/example/repo/blob/main/config.env#L10',
    );
});

test('defense-in-depth excerpt redaction covers compound key names and JWTs', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz';
    const output = githubLeaks.redactExcerpt(`AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwx\nDB_PASSWORD=hunterhunter\nJWT=${jwt}`);
    assert.ok(!output.includes('abcdefghijklmnopqrstuvwx'));
    assert.ok(!output.includes('hunterhunter'));
    assert.ok(!output.includes(jwt));
    assert.ok(output.includes('[JWT REDACTED]'));
});

test('query strings use fixed pagination and preserve literal filters', () => {
    const params = new URLSearchParams(githubLeaks.queryString({
        page: 3,
        status: 'new',
        keyword: 'vendor.example & storage-service',
        q: 'repo:test#path',
    }));
    assert.equal(params.get('page'), '3');
    assert.equal(params.get('page_size'), '25');
    assert.equal(params.get('status'), 'new');
    assert.equal(params.get('keyword'), 'vendor.example & storage-service');
    assert.equal(params.get('q'), 'repo:test#path');

    const deepLink = new URLSearchParams(githubLeaks.queryString({
        page: 9,
        status: 'resolved',
        keyword: 'old-rule',
        q: 'stale search',
    }, 'leak-42'));
    assert.equal(deepLink.get('page'), '1');
    assert.equal(deepLink.get('q'), 'leak-42');
    assert.equal(deepLink.has('status'), false);
    assert.equal(deepLink.has('keyword'), false);
});

function uiHarness(hash = '#github-leaks', permissionCheck = () => true) {
    const source = fs.readFileSync(require.resolve('./github-leaks.js'), 'utf8');
    const elements = new Map();
    const pending = [];
    const timers = [];
    const windowListeners = {};
    const page = {
        id: 'page-github-leaks',
        active: true,
        classList: { contains(name) { return name === 'active' && page.active; } },
    };

    function element(id) {
        if (id === 'page-github-leaks') return page;
        if (!elements.has(id)) {
            const item = {
                id,
                innerHTML: '',
                textContent: '',
                value: '',
                hidden: false,
                disabled: false,
                open: false,
                isConnected: true,
                dataset: {},
                listeners: {},
                classList: { contains: () => false },
                addEventListener(name, fn) { this.listeners[name] = fn; },
                closest(selector) { return selector === '.page' ? page : null; },
                insertAdjacentHTML(_where, value) { this.innerHTML += value; },
                showModal() { this.open = true; },
                close() {
                    this.open = false;
                    if (this.listeners.close) this.listeners.close({ target: this });
                },
                focus() { this.focused = true; },
            };
            elements.set(id, item);
        }
        return elements.get(id);
    }

    const location = { hash };
    const history = {
        replaceState(_state, _title, next) { location.hash = String(next); },
    };
    const context = {
        module: { exports: {} },
        exports: {},
        URL,
        URLSearchParams,
        AbortController,
        console,
        JSON,
        Date,
        Number,
        Math,
        Map,
        Set,
        Promise,
        window: {
            location,
            history,
            __locale: 'zh-CN',
            addEventListener(name, fn) { windowListeners[name] = fn; },
        },
        document: { getElementById: element },
        hasPermission: permissionCheck,
        setTimeout(fn, delay) {
            const entry = { id: timers.length + 1, fn, delay, cleared: false };
            timers.push(entry);
            return entry.id;
        },
        clearTimeout(id) {
            const entry = timers.find(timer => timer.id === id);
            if (entry) entry.cleared = true;
        },
        apiFetch(url, options = {}) {
            return new Promise(resolve => pending.push({ url, options, resolve }));
        },
    };
    context.window.setTimeout = context.setTimeout;
    context.window.clearTimeout = context.clearTimeout;
    vm.runInNewContext(source, context, { filename: 'github-leaks.js' });

    function response(data, status = 200) {
        return { ok: status >= 200 && status < 300, status, json: async () => data };
    }

    function resolveRefresh(batch, options = {}) {
        const finding = options.finding || {
            id: 'leak-1', status: 'new', keyword: 'storage-service', repository: 'example/repo', path: '.env', line: 4,
            secret_type: 'GitHub token', confidence: 'likely', severity: 'high', fingerprint: 'fp-1234567890',
            masked_excerpt: 'TOKEN=••••••••', html_url: 'https://github.com/example/repo/blob/main/.env#L4',
            first_seen_at: '2026-09-01T00:00:00Z', last_seen_at: '2026-09-01T00:01:00Z',
        };
        for (const request of batch) {
            if (request.url.includes('/findings?')) {
                request.resolve(response({ items: [finding], total: 1, page: 1, page_size: 25, total_pages: 1 }));
            } else if (request.url.endsWith('/stats')) {
                request.resolve(response({ total: 1, new: 1, triaged: 0, false_positive: 0, resolved: 0, likely: 1, suspected: 0 }));
            } else if (request.url.endsWith('/runtime')) {
                request.resolve(response({
                    enabled: true,
                    configured: true,
                    running: options.running === true,
                    last_status: options.lastStatus || 'success',
                    last_error: options.lastError || '',
                    last_warning: options.lastWarning || '',
                    rate_remaining: options.rateRemaining === undefined ? 20 : options.rateRemaining,
                    request_timeout_seconds: 45,
                    keywords: ['storage-service', 'vendor.example'],
                    query: '"storage-service" AND "vendor.example" in:file',
                }));
            }
        }
        return finding;
    }

    return { ui: context.module.exports, element, page, pending, timers, location, windowListeners, response, resolveRefresh };
}

function flush() {
    return new Promise(resolve => setImmediate(resolve));
}

test('running and idle refreshes use bounded polling intervals', async () => {
    const running = uiHarness();
    running.ui.init();
    running.resolveRefresh(running.pending.splice(0), { running: true });
    await flush();
    assert.equal(running.timers.filter(timer => !timer.cleared).at(-1).delay, 5000);

    const idle = uiHarness();
    idle.ui.init();
    idle.resolveRefresh(idle.pending.splice(0), { running: false });
    await flush();
    assert.equal(idle.timers.filter(timer => !timer.cleared).at(-1).delay, 30000);
    assert.ok(idle.element('github-leaks-runtime').innerHTML.includes('&quot;storage-service&quot; AND &quot;vendor.example&quot; in:file'));
    assert.ok(!idle.element('github-leaks-content').innerHTML.includes('id="github-leaks-keyword"'));

    const unknownRate = uiHarness();
    unknownRate.ui.init();
    unknownRate.resolveRefresh(unknownRate.pending.splice(0), { rateRemaining: -1 });
    await flush();
    assert.ok(unknownRate.element('github-leaks-runtime').innerHTML.includes('API 剩余额度：—'));
    assert.ok(!unknownRate.element('github-leaks-runtime').innerHTML.includes('API 剩余额度：-1'));
});

test('partial coverage and partial rule failures are warnings instead of complete failures', async () => {
    for (const lastWarning of [
        '7 of 12 rule searches were incomplete or truncated',
        '2 of 12 rule searches failed',
    ]) {
        const partial = uiHarness();
        partial.ui.init();
        partial.resolveRefresh(partial.pending.splice(0), {
            lastStatus: 'partial',
            lastWarning,
            // Keep the legacy field populated to cover cached/older backend responses.
            lastError: lastWarning,
        });
        await flush();
        const html = partial.element('github-leaks-runtime').innerHTML;
        assert.ok(html.includes('最近一次检索部分完成'));
        assert.ok(html.includes('请查看下方规则状态'));
        assert.ok(html.includes('class="is-warning"'));
        assert.ok(!html.includes('最近一次检索失败'));
    }

    const failed = uiHarness();
    failed.ui.init();
    failed.resolveRefresh(failed.pending.splice(0), {
        lastStatus: 'error',
        lastError: 'sanitized provider error',
    });
    await flush();
    assert.ok(failed.element('github-leaks-runtime').innerHTML.includes('最近一次检索失败'));
});

test('run and status mutations use existing configuration and vulnerability permissions', async () => {
    const harness = uiHarness('#github-leaks?id=leak-1', permission => permission !== 'config:write' && permission !== 'vulnerability:write');
    harness.ui.init();
    harness.resolveRefresh(harness.pending.splice(0));
    await flush();
    assert.equal(harness.element('github-leaks-run').disabled, true);
    assert.equal(await harness.ui.updateStatus('leak-1', 'triaged'), false);
    assert.equal(harness.pending.length, 0);
    assert.ok(!harness.element('github-leaks-detail').innerHTML.includes('data-ghl-status'));
});

test('stop hook clears timers and aborts in-flight refreshes', () => {
    const harness = uiHarness();
    harness.ui.init();
    const requests = harness.pending.splice(0);
    harness.element('github-leaks-query').listeners.input();
    harness.ui.stop();
    assert.equal(requests[0].options.signal.aborted, true);
    assert.ok(harness.timers.every(timer => timer.cleared));
});

test('leaving the page prevents stale rendering and further polling', async () => {
    const harness = uiHarness();
    harness.ui.init();
    const requests = harness.pending.splice(0);
    harness.page.active = false;
    harness.resolveRefresh(requests, { running: true });
    await flush();
    assert.equal(harness.element('github-leaks-list').innerHTML, '');
    assert.equal(harness.timers.filter(timer => !timer.cleared).length, 0);
});

test('an older refresh is aborted and cannot overwrite newer findings', async () => {
    const harness = uiHarness();
    harness.ui.init();
    const older = harness.pending.splice(0);
    const latestPromise = harness.element('github-leaks-refresh').listeners.click();
    const latest = harness.pending.splice(0);
    harness.resolveRefresh(latest, {
        finding: {
            id: 'leak-new', status: 'new', keyword: 'storage-service', repository: 'new/repo', path: '.env',
            secret_type: 'API key', fingerprint: 'fp-new', masked_excerpt: 'token=••••••••',
            html_url: 'https://github.com/new/repo/blob/main/.env',
        },
    });
    await latestPromise;
    assert.equal(older[0].options.signal.aborted, true);
    harness.resolveRefresh(older, {
        finding: {
            id: 'leak-old', status: 'new', keyword: 'storage-service', repository: 'old/repo', path: '.env',
            secret_type: 'API key', fingerprint: 'fp-old', masked_excerpt: 'token=••••••••',
            html_url: 'https://github.com/old/repo/blob/main/.env',
        },
    });
    await flush();
    const html = harness.element('github-leaks-list').innerHTML;
    assert.ok(html.includes('new/repo'));
    assert.ok(!html.includes('old/repo'));
});

test('deep-link id is searched safely and opens only the matching finding', async () => {
    const harness = uiHarness('#github-leaks?id=leak-42');
    harness.ui.init();
    const requests = harness.pending.splice(0);
    const listRequest = requests.find(request => request.url.includes('/findings?'));
    const params = new URL('http://example.test' + listRequest.url).searchParams;
    assert.equal(params.get('q'), 'leak-42');
    harness.resolveRefresh(requests, {
        finding: {
            id: 'leak-42', status: 'new', keyword: 'vendor.example', repository: 'org/private-name', path: 'config.yml',
            secret_type: 'API key', fingerprint: 'fp-deep-link', masked_excerpt: 'api_key=••••••••',
            html_url: 'https://github.com/org/private-name/blob/main/config.yml',
        },
    });
    await flush();
    assert.equal(harness.element('github-leaks-dialog').open, true);
    assert.ok(harness.element('github-leaks-detail').innerHTML.includes('fp-deep-link'));
});

test('a deep link received while already on the page starts a targeted refresh', async () => {
    const harness = uiHarness();
    harness.ui.init();
    harness.resolveRefresh(harness.pending.splice(0));
    await flush();
    harness.location.hash = '#github-leaks?id=leak-live';
    harness.windowListeners.hashchange();
    const requests = harness.pending.splice(0);
    const listRequest = requests.find(request => request.url.includes('/findings?'));
    assert.equal(new URL('http://example.test' + listRequest.url).searchParams.get('q'), 'leak-live');
    harness.resolveRefresh(requests, {
        finding: {
            id: 'leak-live', status: 'new', keyword: 'storage-service', repository: 'live/repo', path: '.env',
            secret_type: 'API key', fingerprint: 'fp-live', masked_excerpt: 'token=••••••••',
            html_url: 'https://github.com/live/repo/blob/main/.env',
        },
    });
    await flush();
    assert.equal(harness.element('github-leaks-dialog').open, true);
    assert.ok(harness.element('github-leaks-detail').innerHTML.includes('fp-live'));
});

test('status updates send only the requested state and refresh the list', async () => {
    const harness = uiHarness();
    harness.ui.init();
    harness.resolveRefresh(harness.pending.splice(0));
    await flush();

    const updatePromise = harness.ui.updateStatus('leak-1', 'triaged');
    await flush();
    const patch = harness.pending.shift();
    assert.equal(patch.url, '/api/github-leaks/findings/leak-1/status');
    assert.equal(patch.options.method, 'PATCH');
    assert.deepEqual(JSON.parse(patch.options.body), { status: 'triaged' });
    patch.resolve(harness.response({
        id: 'leak-1', status: 'triaged', keyword: 'storage-service', repository: 'example/repo', path: '.env',
        secret_type: 'GitHub token', fingerprint: 'fp-1234567890', masked_excerpt: 'TOKEN=••••••••',
        html_url: 'https://github.com/example/repo/blob/main/.env',
    }));
    await flush();
    const refresh = harness.pending.splice(0);
    assert.equal(refresh.length, 3);
    harness.resolveRefresh(refresh, {
        finding: {
            id: 'leak-1', status: 'triaged', keyword: 'storage-service', repository: 'example/repo', path: '.env',
            secret_type: 'GitHub token', fingerprint: 'fp-1234567890', masked_excerpt: 'TOKEN=••••••••',
            html_url: 'https://github.com/example/repo/blob/main/.env',
        },
    });
    assert.equal(await updatePromise, true);
});
