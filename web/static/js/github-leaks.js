/* GitHub credential exposure monitoring UI. Secret values must never reach this module. */
const GitHubLeaks = (() => {
    const PAGE_SIZE = 25;
    const POLL_IDLE_MS = 30000;
    const POLL_RUNNING_MS = 5000;
    const STATUS_VALUES = ['new', 'triaged', 'false_positive', 'resolved'];
    const words = {
        title: 'GitHub 凭据泄露监控',
        subtitle: '按多条具名 AND 规则持续检索公开 GitHub 代码；每条规则内的词必须在同一文件中同时命中。命中仅代表疑似泄露，需人工核验并及时轮换凭据。',
        runNow: '立即检索',
        running: '检索中…',
        refresh: '刷新',
        search: '搜索仓库、路径、类型或指纹',
        allStatuses: '全部状态',
        rules: '运行规则',
        rule: 'AND 规则',
        ruleName: '规则名称',
        query: 'Canonical 查询',
        ruleEnabled: '已启用',
        ruleDisabled: '已停用',
        ruleSuccess: '成功',
        ruleNotModified: '未变更',
        rulePartial: '部分完成',
        ruleError: '失败',
        ruleIdle: '尚未运行',
        ruleIncomplete: '结果不完整',
        ruleTruncated: '结果已截断',
        legacyRule: '兼容规则',
        total: '全部命中',
        new: '未审阅',
        triaged: '已审阅',
        false_positive: '误报',
        resolved: '已处置',
        likely: '高可信',
        suspected: '待核验',
        configured: 'GitHub 凭据已配置',
        notConfigured: '尚未配置 GitHub 凭据，请先前往系统设置。',
        enabled: '自动监控已启用',
        disabled: '自动监控已暂停',
        lastRun: '最近检索',
        nextRun: '下次检索',
        duration: '请求超时',
        rateRemaining: 'API 剩余额度',
        rateReset: '额度重置',
        status: '状态',
        keyword: '规则 / 查询',
        target: '仓库 / 位置',
        evidence: '凭据类型 / 指纹',
        confidence: '可信度',
        lastSeen: '最近发现',
        actions: '操作',
        details: '详情',
        empty: '没有匹配的 GitHub 泄露情报。',
        loading: '正在读取 GitHub 泄露情报…',
        previous: '上一页',
        next: '下一页',
        page: '页',
        items: '条',
        repository: '仓库',
        path: '文件位置',
        secretType: '凭据类型',
        fingerprint: '脱敏指纹',
        firstSeen: '首次发现',
        maskedExcerpt: '脱敏证据',
        openGitHub: '在 GitHub 中定位',
        close: '关闭',
        markTriaged: '标记已审阅',
        markFalsePositive: '标记误报',
        markResolved: '标记已处置',
        reopen: '重新打开',
        noData: '—',
        requestFailed: '请求失败，请稍后重试。',
        runAccepted: '检索任务已提交。',
        recentPartial: '最近一次检索部分完成；可用数据已保存，请查看下方规则状态。',
        recentFailure: '最近一次检索失败，请查看服务端脱敏日志。',
        notFound: '未找到指定的泄露情报。',
    };

    const escapeHTML = value => String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[ch]);

    function t(key) {
        const translated = typeof window !== 'undefined' && typeof window.t === 'function'
            ? window.t('githubLeaks.' + key)
            : '';
        return translated && translated !== 'githubLeaks.' + key ? translated : (words[key] || key);
    }

    function safeGitHubURL(value) {
        const raw = String(value == null ? '' : value);
        if (!raw || /[\u0000-\u0020\\]/.test(raw)) return '';
        try {
            const url = new URL(raw);
            if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== 'github.com') return '';
            if (url.username || url.password || (url.port && url.port !== '443')) return '';
            if (url.search || (url.hash && !/^#L\d+(?:-L\d+)?$/.test(url.hash))) return '';
            return url.href;
        } catch (_) {
            return '';
        }
    }

    function redactExcerpt(value) {
        let text = String(value == null ? '' : value).slice(0, 4000);
        text = text.replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi, '[PRIVATE KEY REDACTED]');
        text = text.replace(/\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g, 'gh*_••••••••');
        text = text.replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA••••••••••••••••');
        text = text.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[JWT REDACTED]');
        text = text.replace(/\bxox[baprs]-[A-Za-z0-9-]{16,}\b/gi, 'xox*-••••••••');
        text = text.replace(/((?:^|[\s,{])(?:[A-Za-z0-9_-]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key)[A-Za-z0-9_-]*)(\s*[:=]\s*["']?))[^\s"'`,;]{8,}/gim, '$1••••••••');
        return text;
    }

    function compactFingerprint(value) {
        const text = String(value == null ? '' : value).trim();
        if (!text) return t('noData');
        if (text.length <= 20) return text;
        return text.slice(0, 16) + '…';
    }

    function formatDate(value) {
        if (!value) return t('noData');
        const date = new Date(value);
        if (Number.isNaN(date.valueOf())) return t('noData');
        const locale = typeof window !== 'undefined' && window.__locale === 'en-US' ? 'en-US' : 'zh-CN';
        return date.toLocaleString(locale);
    }

    function normalizeFinding(input) {
        const finding = input && typeof input === 'object' ? input : {};
        const status = STATUS_VALUES.includes(finding.status) ? finding.status : 'new';
        const query = String(finding.query || finding.keyword || '');
        return {
            id: String(finding.id == null ? '' : finding.id),
            status,
            rule_name: String(finding.rule_name || ''),
            query,
            keyword: query,
            repository: String(finding.repository || ''),
            path: String(finding.path || ''),
            line: Number.isFinite(Number(finding.line)) && Number(finding.line) > 0 ? Math.trunc(Number(finding.line)) : 0,
            secret_type: String(finding.secret_type || ''),
            confidence: String(finding.confidence || ''),
            severity: String(finding.severity || ''),
            fingerprint: String(finding.fingerprint || ''),
            masked_excerpt: redactExcerpt(finding.masked_excerpt || ''),
            html_url: safeGitHubURL(finding.html_url),
            first_seen_at: finding.first_seen_at || '',
            last_seen_at: finding.last_seen_at || '',
        };
    }

    function statusBadge(status) {
        const key = STATUS_VALUES.includes(status) ? status : 'new';
        return `<span class="ghl-badge ghl-status-${escapeHTML(key)}">${escapeHTML(t(key))}</span>`;
    }

    function findingLocation(finding) {
        const path = finding.path || t('noData');
        return finding.line ? path + ':' + finding.line : path;
    }

    function ruleCellHTML(finding) {
        const name = String(finding.rule_name || '').trim();
        const query = String(finding.query || finding.keyword || '').trim();
        const nameHTML = name ? `<strong>${escapeHTML(name)}</strong>` : '';
        const queryHTML = query ? `<code>${escapeHTML(query)}</code>` : `<code>${escapeHTML(t('noData'))}</code>`;
        return `<span class="ghl-rule-cell">${nameHTML}${queryHTML}</span>`;
    }

    function rowHTML(rawFinding) {
        const finding = normalizeFinding(rawFinding);
        const url = finding.html_url;
        const location = escapeHTML(findingLocation(finding));
        const target = `<strong>${escapeHTML(finding.repository || t('noData'))}</strong><small>${location}</small>`;
        const linkedTarget = url
            ? `<a class="ghl-location" href="${escapeHTML(url)}" target="_blank" rel="noopener noreferrer">${target}</a>`
            : `<span class="ghl-location">${target}</span>`;
        const confidence = [finding.severity, finding.confidence].filter(Boolean).join(' · ') || t('suspected');
        return `<td>${statusBadge(finding.status)}</td>
            <td>${linkedTarget}</td>
            <td><span class="ghl-secret-type">${escapeHTML(finding.secret_type || t('noData'))}</span><code>${escapeHTML(compactFingerprint(finding.fingerprint))}</code></td>
            <td>${ruleCellHTML(finding)}</td>
            <td>${escapeHTML(confidence)}</td>
            <td>${escapeHTML(formatDate(finding.last_seen_at))}</td>
            <td><button type="button" class="btn-secondary btn-small" data-ghl-detail="${escapeHTML(finding.id)}">${escapeHTML(t('details'))}</button></td>`;
    }

    function statusActionsHTML(finding) {
        if (typeof hasPermission === 'function' && !hasPermission('vulnerability:write')) return '';
        const actions = finding.status === 'new'
            ? [['triaged', 'markTriaged'], ['false_positive', 'markFalsePositive']]
            : finding.status === 'triaged'
                ? [['resolved', 'markResolved'], ['false_positive', 'markFalsePositive']]
                : [['new', 'reopen']];
        return actions.map(([status, label]) => `<button type="button" class="btn-secondary" data-ghl-status="${status}" data-ghl-id="${escapeHTML(finding.id)}">${escapeHTML(t(label))}</button>`).join('');
    }

    function detailHTML(rawFinding) {
        const finding = normalizeFinding(rawFinding);
        const location = findingLocation(finding);
        const link = finding.html_url
            ? `<a class="btn-secondary" href="${escapeHTML(finding.html_url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(t('openGitHub'))}</a>`
            : '';
        const ruleName = finding.rule_name
            ? `<dt>${escapeHTML(t('ruleName'))}</dt><dd>${escapeHTML(finding.rule_name)}</dd>`
            : '';
        return `<div class="ghl-detail-heading"><div>${statusBadge(finding.status)} <span class="ghl-badge">${escapeHTML(finding.secret_type || t('noData'))}</span></div></div>
            <dl class="ghl-detail-list">
                <dt>${escapeHTML(t('repository'))}</dt><dd>${escapeHTML(finding.repository || t('noData'))}</dd>
                <dt>${escapeHTML(t('path'))}</dt><dd>${escapeHTML(location)}</dd>
                ${ruleName}
                <dt>${escapeHTML(t('query'))}</dt><dd>${escapeHTML(finding.query || t('noData'))}</dd>
                <dt>${escapeHTML(t('secretType'))}</dt><dd>${escapeHTML(finding.secret_type || t('noData'))}</dd>
                <dt>${escapeHTML(t('confidence'))}</dt><dd>${escapeHTML([finding.severity, finding.confidence].filter(Boolean).join(' · ') || t('suspected'))}</dd>
                <dt>${escapeHTML(t('fingerprint'))}</dt><dd><code>${escapeHTML(compactFingerprint(finding.fingerprint))}</code></dd>
                <dt>${escapeHTML(t('firstSeen'))}</dt><dd>${escapeHTML(formatDate(finding.first_seen_at))}</dd>
                <dt>${escapeHTML(t('lastSeen'))}</dt><dd>${escapeHTML(formatDate(finding.last_seen_at))}</dd>
            </dl>
            <h3>${escapeHTML(t('maskedExcerpt'))}</h3>
            <pre class="ghl-masked-excerpt">${escapeHTML(finding.masked_excerpt || t('noData'))}</pre>
            <div class="ghl-detail-actions">${statusActionsHTML(finding)}${link}</div>`;
    }

    function queryString(state, overrideQuery) {
        const override = String(overrideQuery || '').trim();
        const params = new URLSearchParams({
            page: override ? '1' : String(Math.max(1, Number(state.page) || 1)),
            page_size: String(PAGE_SIZE),
        });
        if (!override) {
            if (state.status) params.set('status', state.status);
            if (state.keyword) params.set('keyword', state.keyword);
        }
        const query = override || String(state.q || '').trim();
        if (query) params.set('q', query);
        return params.toString();
    }

    function validDeepLinkID(value) {
        const id = String(value || '').trim();
        return id.length > 0 && id.length <= 160 && !/[\u0000-\u001f\u007f]/.test(id) ? id : '';
    }

    function deepLinkID() {
        if (typeof window === 'undefined') return '';
        const parts = String(window.location && window.location.hash || '').replace(/^#/, '').split('?');
        if (parts[0] !== 'github-leaks' || parts.length < 2) return '';
        return validDeepLinkID(new URLSearchParams(parts.slice(1).join('?')).get('id'));
    }

    let root;
    let page;
    let bound = false;
    let timer = null;
    let debounce = null;
    let controller = null;
    let sequence = 0;
    let detailSequence = 0;
    let focusReturn = null;
    let pendingDeepLink = '';
    let runtimeState = {};
    let findings = new Map();
    let state = { page: 1, status: '', q: '' };
    let hashBound = false;

    const el = id => document.getElementById('github-leaks-' + id);
    const active = () => {
        page = page || document.getElementById('page-github-leaks') || (root && root.closest ? root.closest('.page') : null);
        return !!root && (!page || !page.classList || page.classList.contains('active'));
    };

    async function request(path, options = {}) {
        const response = await apiFetch('/api/github-leaks' + path, options);
        let data = {};
        try { data = await response.json(); } catch (_) {}
        if (!response.ok) {
            const error = new Error(t('requestFailed'));
            error.status = response.status;
            throw error;
        }
        return data && typeof data === 'object' ? data : {};
    }

    function showError(message) {
        const target = el('error');
        if (!target) return;
        target.textContent = message || '';
        target.hidden = !message;
    }

    function layout() {
        root.innerHTML = `<div class="ghl-toolbar">
                <div><h2>${escapeHTML(t('title'))}</h2><p>${escapeHTML(t('subtitle'))}</p></div>
                <div class="ghl-toolbar-actions"><button id="github-leaks-refresh" type="button" class="btn-secondary">${escapeHTML(t('refresh'))}</button><button id="github-leaks-run" type="button" class="btn-primary">${escapeHTML(t('runNow'))}</button></div>
            </div>
            <div id="github-leaks-runtime" class="ghl-runtime" aria-live="polite"></div>
            <div id="github-leaks-stats" class="ghl-stats"></div>
            <div id="github-leaks-error" class="ghl-error" role="alert" hidden></div>
            <form id="github-leaks-filters" class="ghl-filters">
                <input id="github-leaks-query" type="search" maxlength="200" placeholder="${escapeHTML(t('search'))}" aria-label="${escapeHTML(t('search'))}">
                <select id="github-leaks-status" aria-label="${escapeHTML(t('allStatuses'))}"><option value="">${escapeHTML(t('allStatuses'))}</option>${STATUS_VALUES.map(status => `<option value="${status}">${escapeHTML(t(status))}</option>`).join('')}</select>
            </form>
            <div class="ghl-table-wrap"><table class="ghl-table"><thead><tr>${['status', 'target', 'evidence', 'keyword', 'confidence', 'lastSeen', 'actions'].map(key => `<th>${escapeHTML(t(key))}</th>`).join('')}</tr></thead><tbody id="github-leaks-list"></tbody></table><p id="github-leaks-empty" class="ghl-empty">${escapeHTML(t('loading'))}</p></div>
            <div class="ghl-pagination"><span id="github-leaks-count"></span><button id="github-leaks-prev" type="button" class="btn-secondary">${escapeHTML(t('previous'))}</button><span id="github-leaks-page"></span><button id="github-leaks-next" type="button" class="btn-secondary">${escapeHTML(t('next'))}</button></div>
            <dialog id="github-leaks-dialog" aria-labelledby="github-leaks-dialog-title"><header><h2 id="github-leaks-dialog-title"></h2><button id="github-leaks-close" type="button" class="btn-secondary">${escapeHTML(t('close'))}</button></header><div id="github-leaks-detail"></div></dialog>`;

        el('filters').addEventListener('submit', event => event.preventDefault());
        el('query').addEventListener('input', () => {
            clearTimeout(debounce);
            debounce = setTimeout(filtersChanged, 300);
        });
        el('status').addEventListener('change', filtersChanged);
        el('refresh').addEventListener('click', refresh);
        el('run').addEventListener('click', runNow);
        el('prev').addEventListener('click', () => { if (state.page > 1) { state.page--; refresh(); } });
        el('next').addEventListener('click', () => { state.page++; refresh(); });
        el('close').addEventListener('click', closeDetail);
        el('dialog').addEventListener('click', event => { if (event.target === el('dialog')) closeDetail(); });
        el('dialog').addEventListener('cancel', event => { event.preventDefault(); closeDetail(); });
        el('dialog').addEventListener('close', () => {
            detailSequence++;
            clearDetailHash();
            if (focusReturn && focusReturn.isConnected && typeof focusReturn.focus === 'function') focusReturn.focus();
            focusReturn = null;
        });
        root.addEventListener('click', event => {
            const detailButton = event.target.closest && event.target.closest('[data-ghl-detail]');
            if (detailButton) {
                openDetail(detailButton.dataset.ghlDetail, detailButton, true);
                return;
            }
            const statusButton = event.target.closest && event.target.closest('[data-ghl-status]');
            if (statusButton) updateStatus(statusButton.dataset.ghlId, statusButton.dataset.ghlStatus, statusButton);
        });
    }

    function filtersChanged() {
        state = {
            page: 1,
            status: el('status').value || '',
            q: el('query').value.trim(),
        };
        pendingDeepLink = '';
        refresh();
    }

    function handleHashChange() {
        const id = deepLinkID();
        if (!id || !active()) return;
        pendingDeepLink = id;
        refresh();
    }

    function renderRuntime(runtime) {
        runtimeState = runtime && typeof runtime === 'object' ? runtime : {};
        const configured = runtimeState.configured === true;
        const running = runtimeState.running === true;
        const enabled = runtimeState.enabled === true;
        const runButton = el('run');
        const canExecute = typeof hasPermission !== 'function' || hasPermission('config:write');
        runButton.disabled = running || !configured || !canExecute;
        runButton.textContent = running ? t('running') : t('runNow');
        const seconds = Math.max(30, Number(runtimeState.request_timeout_seconds) || 30);
        const items = [
            `<span class="ghl-runtime-state ${configured ? 'is-ok' : 'is-warning'}">${escapeHTML(configured ? t('configured') : t('notConfigured'))}</span>`,
            `<span>${escapeHTML(enabled ? t('enabled') : t('disabled'))}</span>`,
            `<span>${escapeHTML(t('duration'))}：${escapeHTML(seconds)}s</span>`,
            `<span>${escapeHTML(t('lastRun'))}：${escapeHTML(formatDate(runtimeState.last_run_at))}</span>`,
            `<span>${escapeHTML(t('nextRun'))}：${escapeHTML(formatDate(runtimeState.next_run_at))}</span>`,
            `<span>${escapeHTML(t('rateRemaining'))}：${Number.isFinite(Number(runtimeState.rate_remaining)) && Number(runtimeState.rate_remaining) >= 0 ? escapeHTML(Number(runtimeState.rate_remaining)) : escapeHTML(t('noData'))}</span>`,
            `<span>${escapeHTML(t('rateReset'))}：${escapeHTML(formatDate(runtimeState.rate_reset_at))}</span>`,
        ];
        const rulesHTML = runtimeRulesHTML(runtimeState);
        if (rulesHTML) items.push(rulesHTML);
        const lastStatus = String(runtimeState.last_status || '').trim().toLowerCase();
        if (lastStatus === 'partial') {
            items.push(`<span class="is-warning">${escapeHTML(t('recentPartial'))}</span>`);
        } else if (lastStatus === 'error' || lastStatus === 'rate_limited' || lastStatus === 'cancelled' || (!lastStatus && runtimeState.last_error)) {
            items.push(`<span class="is-error">${escapeHTML(t('recentFailure'))}</span>`);
        }
        el('runtime').innerHTML = items.join('');
    }

    function normalizeRuntimeRules(runtime) {
        const value = runtime && typeof runtime === 'object' ? runtime : {};
        const source = Array.isArray(value.rules) ? value.rules.slice(0, 32) : [];
        const allowedStatuses = new Set(['idle', 'success', 'not_modified', 'partial', 'error']);
        const rules = source.map(rule => {
            const lastStatus = String(rule && rule.last_status || '').trim().toLowerCase();
            return {
                name: String(rule && rule.name || '').trim(),
                enabled: !!rule && rule.enabled === true,
                query: String(rule && rule.query || '').trim(),
                last_status: allowedStatuses.has(lastStatus) ? lastStatus : '',
                last_error: redactExcerpt(String(rule && rule.last_error || '')).slice(0, 500).trim(),
                incomplete: !!rule && rule.incomplete === true,
                truncated: !!rule && rule.truncated === true,
            };
        });
        if (!rules.length) {
            const legacyQuery = String(value.query || '').trim();
            if (legacyQuery) rules.push({
                name: t('legacyRule'),
                enabled: value.enabled === true,
                query: legacyQuery,
                last_status: '',
                last_error: '',
                incomplete: false,
                truncated: false,
            });
        }
        return rules;
    }

    function runtimeRulesHTML(runtime) {
        const rules = normalizeRuntimeRules(runtime);
        if (!rules.length) return '';
        const statusLabels = {
            success: t('ruleSuccess'),
            not_modified: t('ruleNotModified'),
            partial: t('rulePartial'),
            error: t('ruleError'),
            idle: t('ruleIdle'),
        };
        const rows = rules.map(rule => {
            const stateClass = rule.enabled ? 'is-enabled' : 'is-disabled';
            const stateLabel = rule.enabled ? t('ruleEnabled') : t('ruleDisabled');
            const status = rule.last_status
                ? `<span class="ghl-rule-state is-${rule.last_status.replace('_', '-')}">${escapeHTML(statusLabels[rule.last_status])}</span>`
                : '';
            const incomplete = rule.incomplete
                ? `<span class="ghl-rule-state is-incomplete">${escapeHTML(t('ruleIncomplete'))}</span>`
                : '';
            const truncated = rule.truncated
                ? `<span class="ghl-rule-state is-truncated">${escapeHTML(t('ruleTruncated'))}</span>`
                : '';
            const error = rule.last_error
                ? `<small class="ghl-runtime-rule-error">${escapeHTML(rule.last_error)}</small>`
                : '';
            return `<li class="ghl-runtime-rule"><span class="ghl-runtime-rule-name"><strong>${escapeHTML(rule.name || t('noData'))}</strong><span class="ghl-rule-state ${stateClass}">${escapeHTML(stateLabel)}</span></span><span class="ghl-runtime-rule-result"><code>${escapeHTML(rule.query || t('noData'))}</code><span class="ghl-runtime-rule-meta">${status}${incomplete}${truncated}</span>${error}</span></li>`;
        }).join('');
        return `<div class="ghl-runtime-rules-wrap"><strong>${escapeHTML(t('rules'))}：</strong><ul class="ghl-runtime-rules">${rows}</ul></div>`;
    }

    function renderStats(stats) {
        const data = stats && typeof stats === 'object' ? stats : {};
        const keys = ['total', 'new', 'triaged', 'false_positive', 'resolved', 'likely', 'suspected'];
        el('stats').innerHTML = keys.map(key => `<div class="ghl-stat"><span>${escapeHTML(t(key))}</span><strong>${escapeHTML(Number(data[key] || 0).toLocaleString())}</strong></div>`).join('');
    }

    function renderList(list) {
        const items = Array.isArray(list.items) ? list.items.map(normalizeFinding) : [];
        findings = new Map(items.filter(item => item.id).map(item => [item.id, item]));
        el('list').innerHTML = items.map(item => `<tr>${rowHTML(item)}</tr>`).join('');
        el('empty').textContent = t('empty');
        el('empty').hidden = items.length > 0;
        const total = Math.max(0, Number(list.total) || 0);
        const currentPage = Math.max(1, Number(list.page) || state.page);
        const totalPages = Math.max(1, Number(list.total_pages) || Math.ceil(total / PAGE_SIZE));
        state.page = currentPage;
        el('count').textContent = `${total.toLocaleString()} ${t('items')}`;
        el('page').textContent = `${currentPage} / ${totalPages} ${t('page')}`;
        el('prev').disabled = currentPage <= 1;
        el('next').disabled = currentPage >= totalPages;

        if (pendingDeepLink) {
            const target = findings.get(pendingDeepLink);
            const requested = pendingDeepLink;
            pendingDeepLink = '';
            if (target) openDetail(requested, null, false);
            else showError(t('notFound'));
        }
    }

    function scheduleRefresh(delay) {
        clearTimeout(timer);
        if (!active()) return;
        timer = setTimeout(refresh, delay);
    }

    async function refresh() {
        if (!active()) {
            clearTimeout(timer);
            if (controller) controller.abort();
            return;
        }
        clearTimeout(timer);
        if (controller) controller.abort();
        controller = new AbortController();
        const currentSequence = ++sequence;
        const deepQuery = pendingDeepLink;
        try {
            const [list, stats, runtime] = await Promise.all([
                request('/findings?' + queryString(state, deepQuery), { signal: controller.signal }),
                request('/stats', { signal: controller.signal }),
                request('/runtime', { signal: controller.signal }),
            ]);
            if (currentSequence !== sequence || !active()) return;
            showError('');
            renderRuntime(runtime);
            renderStats(stats);
            renderList(list);
            scheduleRefresh(runtime.running === true ? POLL_RUNNING_MS : POLL_IDLE_MS);
        } catch (error) {
            if (currentSequence !== sequence || error.name === 'AbortError' || !active()) return;
            showError(t('requestFailed'));
            scheduleRefresh(POLL_IDLE_MS);
        }
    }

    async function runNow() {
        const button = el('run');
        if (!button || button.disabled) return;
        button.disabled = true;
        button.textContent = t('running');
        try {
            const result = await request('/run', { method: 'POST' });
            if (result.accepted !== true) throw new Error(t('requestFailed'));
            showError('');
            await refresh();
            scheduleRefresh(1500);
        } catch (_) {
            showError(t('requestFailed'));
            renderRuntime(runtimeState);
        }
    }

    function setDetailHash(id) {
        if (typeof window === 'undefined' || !window.history || typeof window.history.replaceState !== 'function') return;
        window.history.replaceState(null, '', '#github-leaks?id=' + encodeURIComponent(id));
    }

    function clearDetailHash() {
        if (typeof window === 'undefined' || !window.location || !String(window.location.hash || '').startsWith('#github-leaks?')) return;
        if (window.history && typeof window.history.replaceState === 'function') window.history.replaceState(null, '', '#github-leaks');
    }

    function openDetail(id, button, updateHash) {
        const cleanID = validDeepLinkID(id);
        const finding = findings.get(cleanID);
        if (!finding) return false;
        const dialog = el('dialog');
        focusReturn = button || focusReturn;
        detailSequence++;
        el('dialog-title').textContent = finding.repository || finding.id;
        el('detail').innerHTML = detailHTML(finding);
        if (updateHash !== false) setDetailHash(finding.id);
        if (dialog && !dialog.open && typeof dialog.showModal === 'function') dialog.showModal();
        return true;
    }

    function closeDetail() {
        const dialog = el('dialog');
        if (dialog && dialog.open && typeof dialog.close === 'function') dialog.close();
        else clearDetailHash();
    }

    async function updateStatus(id, status, button) {
        const cleanID = validDeepLinkID(id);
        const canWrite = typeof hasPermission !== 'function' || hasPermission('vulnerability:write');
        if (!canWrite || !cleanID || !STATUS_VALUES.includes(status)) return false;
        if (button) button.disabled = true;
        try {
            const updated = normalizeFinding(await request('/findings/' + encodeURIComponent(cleanID) + '/status', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status }),
            }));
            if (updated.id) {
                findings.set(updated.id, updated);
                if (el('dialog') && el('dialog').open) {
                    el('dialog-title').textContent = updated.repository || updated.id;
                    el('detail').innerHTML = detailHTML(updated);
                }
            }
            await refresh();
            return true;
        } catch (_) {
            showError(t('requestFailed'));
            return false;
        } finally {
            if (button && button.isConnected) button.disabled = false;
        }
    }

    function init() {
        root = document.getElementById('github-leaks-content');
        if (!root) return;
        page = document.getElementById('page-github-leaks') || (root.closest ? root.closest('.page') : null);
        if (!bound) {
            layout();
            bound = true;
        }
        if (!hashBound && typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
            window.addEventListener('hashchange', handleHashChange);
            hashBound = true;
        }
        pendingDeepLink = deepLinkID();
        refresh();
    }

    function stop() {
        clearTimeout(timer);
        clearTimeout(debounce);
        timer = null;
        debounce = null;
        if (controller) controller.abort();
        controller = null;
        sequence++;
        detailSequence++;
        pendingDeepLink = '';
        focusReturn = null;
        const dialog = typeof document !== 'undefined' ? document.getElementById('github-leaks-dialog') : null;
        if (dialog && dialog.open && typeof dialog.close === 'function') dialog.close();
    }

    return {
        init,
        stop,
        escapeHTML,
        safeGitHubURL,
        redactExcerpt,
        normalizeFinding,
        normalizeRuntimeRules,
        runtimeRulesHTML,
        rowHTML,
        detailHTML,
        queryString,
        deepLinkID,
        updateStatus,
        words,
        constants: { PAGE_SIZE, POLL_IDLE_MS, POLL_RUNNING_MS, STATUS_VALUES },
    };
})();

function initGitHubLeaks() { GitHubLeaks.init(); }
function stopGitHubLeaksPage() { GitHubLeaks.stop(); }
if (typeof window !== 'undefined') {
    window.initGitHubLeaks = initGitHubLeaks;
    window.stopGitHubLeaksPage = stopGitHubLeaksPage;
}
if (typeof module !== 'undefined' && module.exports) module.exports = GitHubLeaks;
