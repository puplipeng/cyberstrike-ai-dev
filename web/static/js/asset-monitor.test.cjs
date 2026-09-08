const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const assetMonitor = require('./asset-monitor.js');

test('root domain normalization accepts domains and rejects URL or wildcard input', () => {
    assert.equal(assetMonitor.normalizeRootDomain(' KUAISHOU.COM. '), 'kuaishou.com');
    assert.equal(assetMonitor.normalizeRootDomain('sub.example.com'), 'sub.example.com');
    for (const value of [
        'https://kuaishou.com',
        '*.kuaishou.com',
        'kuaishou.com/path',
        'user@kuaishou.com',
        'kuaishou.com:443',
        'localhost',
        '-bad.example',
        'bad-.example',
    ]) {
        assert.equal(assetMonitor.normalizeRootDomain(value), '', value);
    }
});

test('monitor, run history, and discovered asset HTML escape untrusted text', () => {
    const marker = '<img src=x onerror=alert(1)>';
    const monitorHTML = assetMonitor.rowHTML({
        id: 'monitor-1',
        project_id: 'project-1',
        project_name: marker,
        name: '<script>alert(1)</script>',
        root_domain: 'safe.example</code><svg onload=alert(1)>',
        provider: '<b>bad</b>',
        enabled: true,
        last_status: 'error',
        last_error: marker,
        recent_new_count: 2,
    });
    const historyHTML = assetMonitor.historyHTML([{
        id: 'run-1',
        status: 'error',
        trigger: 'manual',
        new_count: 1,
        error: '<script>history()</script>',
    }], 'monitor-1');
    const assetsHTML = assetMonitor.runAssetsHTML([{
        host: '<svg onload=bad()>',
        port: 443,
        protocol: marker,
        title: '<script>asset()</script>',
        observed_at: '2026-09-04T00:00:00Z',
    }]);
    const html = monitorHTML + historyHTML + assetsHTML;
    for (const tag of ['<script', '<img', '<svg', '<b>']) assert.ok(!html.includes(tag), tag);
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /data-monitor-id="monitor-1"/);
});

test('list and history response parsing accepts wrapped and legacy arrays', () => {
    assert.deepEqual(
        assetMonitor.parseListResponse({ items: [{ id: 'one' }], total: 8 }).items,
        [{ id: 'one' }],
    );
    assert.equal(assetMonitor.parseListResponse([{ id: 'one' }]).total, 1);
    assert.deepEqual(assetMonitor.parseListResponse({ monitors: [{ id: 'two' }] }).items, [{ id: 'two' }]);
    assert.deepEqual(assetMonitor.parseRunsResponse({ items: [{ id: 'run-1' }] }), [{ id: 'run-1' }]);
    assert.deepEqual(assetMonitor.parseRunsResponse({ runs: [{ id: 'run-2' }] }), [{ id: 'run-2' }]);
});

test('list query uses the flat asset-monitors API pagination and filters', () => {
    const params = new URLSearchParams(assetMonitor.queryString({
        page: 3,
        projectId: 'project-42',
        enabled: 'false',
    }));
    assert.equal(assetMonitor.constants.API_ROOT, '/api/asset-monitors');
    assert.equal(params.get('limit'), '25');
    assert.equal(params.get('offset'), '50');
    assert.equal(params.get('project_id'), 'project-42');
    assert.equal(params.get('enabled'), 'false');
    assert.equal(assetMonitor.constants.MIN_INTERVAL_MINUTES, 60);
    assert.equal(assetMonitor.constants.MAX_INTERVAL_MINUTES, 10080);
    assert.equal(assetMonitor.constants.DEFAULT_INTERVAL_MINUTES, 1440);
    assert.equal(assetMonitor.constants.MAX_RESULTS, 1000);
    assert.equal(assetMonitor.constants.DEFAULT_MAX_RESULTS, 200);
});

test('template, router, RBAC, i18n, and compact scrolling styles are wired', () => {
    const base = path.resolve(__dirname, '..', '..');
    const html = fs.readFileSync(path.join(base, 'templates', 'index.html'), 'utf8');
    const router = fs.readFileSync(path.join(__dirname, 'router.js'), 'utf8');
    const auth = fs.readFileSync(path.join(__dirname, 'auth.js'), 'utf8');
    const guards = fs.readFileSync(path.join(__dirname, 'rbac-guards.js'), 'utf8');
    const css = fs.readFileSync(path.join(base, 'static', 'css', 'asset-monitor.css'), 'utf8');
    const zh = JSON.parse(fs.readFileSync(path.join(base, 'static', 'i18n', 'zh-CN.json'), 'utf8'));
    const en = JSON.parse(fs.readFileSync(path.join(base, 'static', 'i18n', 'en-US.json'), 'utf8'));

    assert.match(html, /data-page="asset-monitor"/);
    assert.match(html, /id="page-asset-monitor"/);
    assert.match(html, /asset-monitor\.css\?v=/);
    assert.match(html, /asset-monitor\.js\?v=/);
    assert.match(html, /router\.js\?v=20260904-assetmonitor1/);
    assert.match(html, /auth\.js\?v=20260904-assetmonitor1/);
    assert.match(html, /rbac-guards\.js\?v=20260904-assetmonitor1/);
    assert.match(router, /currentPage === 'asset-monitor'[\s\S]*stopAssetMonitorPage/);
    assert.match(router, /case 'asset-monitor':[\s\S]*initAssetMonitor/);
    assert.match(auth, /'asset-monitor': 'asset:read'/);
    assert.match(auth, /data-require-permissions/);
    assert.match(auth, /allOf[\s\S]*every\(hasPermission\)/);
    assert.match(html, /data-require-permissions="asset:write project:write"/);
    assert.match(guards, /runAssetMonitorNow: \['asset:write', 'project:write', 'fofa:execute'\]/);
    assert.match(guards, /deleteAssetMonitor: \['asset:delete', 'project:write'\]/);
    assert.match(css, /\.am-topbar\{[^}]*overflow-x:auto/);
    assert.match(css, /\.am-table-wrap\{[^}]*overflow:auto/);
    assert.match(css, /\.am-table thead\{[^}]*position:sticky/);
    assert.deepEqual(Object.keys(zh.assetMonitor).sort(), Object.keys(en.assetMonitor).sort());
    assert.equal(zh.nav.assetMonitor, '资产监控');
    assert.equal(en.nav.assetMonitor, 'Asset Monitoring');
});

test('global write guard treats asset monitor permission arrays as AND', () => {
    const source = fs.readFileSync(path.join(__dirname, 'rbac-guards.js'), 'utf8');
    const executed = [];
    const denied = [];
    const allowed = new Set(['asset:write', 'project:write']);
    const context = {
        window: {
            runAssetMonitorNow() { executed.push('run'); },
            t() { return 'forbidden'; },
        },
        hasPermission(permission) { return allowed.has(permission); },
        requirePermission(permissions) {
            const values = Array.isArray(permissions) ? permissions : [permissions];
            return values.some(permission => allowed.has(permission));
        },
        notifyApiError(message) { denied.push(message); },
        showNotification() {},
    };
    vm.runInNewContext(source, context, { filename: 'rbac-guards.js' });
    context.window.runAssetMonitorNow();
    assert.deepEqual(executed, []);
    assert.deepEqual(denied, ['forbidden']);

    allowed.add('fofa:execute');
    context.window.runAssetMonitorNow();
    assert.deepEqual(executed, ['run']);
});

function createUIHarness(allowedPermissions) {
    const source = fs.readFileSync(require.resolve('./asset-monitor.js'), 'utf8');
    const elements = new Map();
    const pending = [];
    const timers = [];
    const notifications = [];
    const permissionRequests = [];
    const allowed = allowedPermissions ? new Set(allowedPermissions) : null;
    const page = {
        id: 'page-asset-monitor',
        active: true,
        classList: { contains(name) { return name === 'active' && page.active; } },
    };

    function element(id) {
        if (id === 'page-asset-monitor') return page;
        if (!elements.has(id)) {
            const item = {
                id,
                innerHTML: '',
                textContent: '',
                value: '',
                hidden: false,
                disabled: false,
                checked: false,
                open: false,
                isConnected: true,
                dataset: {},
                listeners: {},
                attributes: {},
                classList: { contains() { return false; } },
                addEventListener(name, fn) { this.listeners[name] = fn; },
                closest(selector) { return selector === '.page' ? page : null; },
                setAttribute(name, value) {
                    this.attributes[name] = String(value);
                    if (name === 'open') this.open = true;
                },
                removeAttribute(name) {
                    delete this.attributes[name];
                    if (name === 'open') this.open = false;
                },
                reset() {},
                focus() { this.focused = true; },
                showModal() { this.open = true; },
                close() {
                    this.open = false;
                    if (this.listeners.close) this.listeners.close({ target: this });
                },
                scrollIntoView() {},
            };
            elements.set(id, item);
        }
        return elements.get(id);
    }

    const location = { hash: '#asset-monitor?project=project-1' };
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
        document: {
            activeElement: null,
            getElementById: element,
            addEventListener() {},
        },
        window: {
            location,
            history,
            __locale: 'zh-CN',
            addEventListener() {},
        },
        hasPermission(permission) { return !allowed || allowed.has(permission); },
        requirePermission(permissions) {
            permissionRequests.push(Array.isArray(permissions) ? permissions.slice() : [permissions]);
            const list = Array.isArray(permissions) ? permissions : [permissions];
            return list.every(permission => !allowed || allowed.has(permission));
        },
        showNotification(message, type) { notifications.push({ message, type }); },
        appConfirm: async () => true,
        setTimeout(fn, delay) {
            const timer = { id: timers.length + 1, fn, delay, cleared: false };
            timers.push(timer);
            return timer.id;
        },
        clearTimeout(id) {
            const timer = timers.find(item => item.id === id);
            if (timer) timer.cleared = true;
        },
        apiFetch(url, options) {
            return new Promise(resolve => pending.push({
                url,
                options: options || {},
                resolve,
                resolved: false,
            }));
        },
    };
    context.window.setTimeout = context.setTimeout;
    context.window.clearTimeout = context.clearTimeout;
    vm.runInNewContext(source, context, { filename: 'asset-monitor.js' });

    function response(data, status) {
        const code = status == null ? 200 : status;
        return { ok: code >= 200 && code < 300, status: code, json: async () => data };
    }

    function take(predicate) {
        const item = pending.find(entry => !entry.resolved && predicate(entry));
        assert.ok(item, 'expected pending request');
        item.resolved = true;
        return item;
    }

    function resolve(item, data, status) {
        item.resolve(response(data, status));
    }

    return {
        api: context.module.exports,
        context,
        elements,
        page,
        pending,
        timers,
        notifications,
        permissionRequests,
        take,
        resolve,
    };
}

const flush = () => new Promise(resolve => setImmediate(resolve));

async function initializeHarness(harness, monitor) {
    harness.api.init();
    const projectsRequest = harness.take(item => item.url.startsWith('/api/projects?'));
    const monitorsRequest = harness.take(item => item.url.startsWith('/api/asset-monitors?'));
    harness.resolve(projectsRequest, { projects: [{ id: 'project-1', name: 'Kuaishou' }] });
    harness.resolve(monitorsRequest, {
        items: [monitor],
        total: 1,
    });
    await flush();
    await flush();
    return { projectsRequest, monitorsRequest };
}

test('active page polls quickly while running and stop clears timers and aborts requests', async () => {
    const harness = createUIHarness();
    const requests = await initializeHarness(harness, {
        id: 'monitor-1',
        project_id: 'project-1',
        name: 'Kuaishou assets',
        root_domain: 'kuaishou.com',
        provider: 'quake',
        enabled: true,
        interval_minutes: 60,
        last_status: 'running',
        last_error: '<script>unsafe</script>',
        recent_new_count: 3,
    });

    const list = harness.elements.get('asset-monitor-list');
    assert.match(list.innerHTML, /Kuaishou assets/);
    assert.ok(!list.innerHTML.includes('<script>unsafe</script>'));
    assert.ok(harness.timers.some(item => item.delay === 5000 && !item.cleared));

    harness.page.active = false;
    harness.api.stop();
    assert.ok(harness.timers.filter(item => item.delay === 5000).every(item => item.cleared));
    assert.equal(requests.monitorsRequest.options.signal.aborted, true);
    assert.equal(requests.projectsRequest.options.signal.aborted, true);
});

test('run now posts to the flat endpoint then refreshes and accelerates polling', async () => {
    const harness = createUIHarness();
    await initializeHarness(harness, {
        id: 'monitor-1',
        project_id: 'project-1',
        name: 'Kuaishou assets',
        root_domain: 'kuaishou.com',
        enabled: true,
        interval_minutes: 60,
        last_status: 'idle',
    });

    const button = { disabled: false, isConnected: true };
    const operation = harness.api.runNow('monitor-1', button);
    const runRequest = harness.take(item => item.url === '/api/asset-monitors/monitor-1/run');
    assert.equal(runRequest.options.method, 'POST');
    assert.equal(runRequest.options.body, undefined);
    harness.resolve(runRequest, { id: 'run-1', status: 'queued' }, 202);
    await flush();

    const refreshRequest = harness.take(item => item.url.startsWith('/api/asset-monitors?'));
    harness.resolve(refreshRequest, {
        items: [{
            id: 'monitor-1',
            project_id: 'project-1',
            name: 'Kuaishou assets',
            root_domain: 'kuaishou.com',
            enabled: true,
            interval_minutes: 60,
            last_status: 'queued',
        }],
        total: 1,
    });
    assert.equal(await operation, true);
    assert.ok(harness.notifications.some(item => item.type === 'success'));
    assert.ok(harness.timers.some(item => item.delay === 1200 && !item.cleared));
    harness.api.stop();
});

test('run now requires asset, project, and recon permissions together', async () => {
    const harness = createUIHarness(['asset:read', 'asset:write', 'project:write']);
    await initializeHarness(harness, {
        id: 'monitor-1',
        project_id: 'project-1',
        name: 'Kuaishou assets',
        root_domain: 'kuaishou.com',
        enabled: true,
        interval_minutes: 1440,
        max_results: 200,
        last_status: 'idle',
    });

    assert.equal(await harness.api.runNow('monitor-1', { disabled: false, isConnected: true }), false);
    assert.deepEqual(
        Array.from(harness.permissionRequests.at(-1)),
        ['fofa:execute'],
    );
    assert.equal(
        harness.pending.some(item => !item.resolved && item.url.endsWith('/monitor-1/run')),
        false,
    );
    harness.api.stop();
});

test('new monitor defaults and POST payload match backend limits', async () => {
    const harness = createUIHarness();
    await initializeHarness(harness, {
        id: 'monitor-1',
        project_id: 'project-1',
        name: 'Existing monitor',
        root_domain: 'example.com',
        enabled: false,
        interval_minutes: 1440,
        max_results: 200,
        last_status: 'disabled',
    });

    assert.equal(await harness.api.openEditor('', { isConnected: true }), true);
    assert.equal(harness.elements.get('asset-monitor-editor-interval').value, '1440');
    assert.equal(harness.elements.get('asset-monitor-editor-max-results').value, '200');
    harness.elements.get('asset-monitor-editor-name').value = 'Kuaishou public assets';
    harness.elements.get('asset-monitor-editor-domain').value = 'kuaishou.com';
    harness.elements.get('asset-monitor-editor-project').value = 'project-1';
    harness.elements.get('asset-monitor-editor-enabled').checked = true;

    harness.elements.get('asset-monitor-editor-interval').value = '59';
    assert.equal(await harness.api.save(), false);
    assert.match(harness.elements.get('asset-monitor-editor-error').textContent, /60/);
    harness.elements.get('asset-monitor-editor-interval').value = '1440';
    harness.elements.get('asset-monitor-editor-max-results').value = '1001';
    assert.equal(await harness.api.save(), false);
    assert.match(harness.elements.get('asset-monitor-editor-error').textContent, /1000/);
    harness.elements.get('asset-monitor-editor-max-results').value = '200';

    const operation = harness.api.save();
    const createRequest = harness.take(item => item.url === '/api/asset-monitors' && item.options.method === 'POST');
    assert.deepEqual(
        JSON.parse(createRequest.options.body),
        {
            project_id: 'project-1',
            name: 'Kuaishou public assets',
            root_domain: 'kuaishou.com',
            provider: 'quake',
            enabled: true,
            interval_minutes: 1440,
            max_results: 200,
        },
    );
    harness.resolve(createRequest, { id: 'monitor-2' }, 201);
    await flush();
    const refreshRequest = harness.take(item => item.url.startsWith('/api/asset-monitors?'));
    harness.resolve(refreshRequest, { items: [], total: 0 });
    assert.equal(await operation, true);
    harness.api.stop();
});
