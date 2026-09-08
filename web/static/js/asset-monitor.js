/* Project asset discovery monitor UI. All server-provided text is escaped before HTML insertion. */
const AssetMonitorPage = (() => {
    const API_ROOT = '/api/asset-monitors';
    const PAGE_SIZE = 25;
    const POLL_IDLE_MS = 30000;
    const POLL_RUNNING_MS = 5000;
    const RUN_HISTORY_LIMIT = 50;
    const MIN_INTERVAL_MINUTES = 60;
    const MAX_INTERVAL_MINUTES = 10080;
    const DEFAULT_INTERVAL_MINUTES = 1440;
    const MAX_RESULTS = 1000;
    const DEFAULT_MAX_RESULTS = 200;
    const STATUS_VALUES = new Set(['idle', 'queued', 'running', 'success', 'partial', 'error', 'disabled']);
    const RUN_STATUS_VALUES = new Set(['queued', 'running', 'success', 'partial', 'error', 'cancelled']);
    const words = {
        allProjects: '全部项目',
        allStates: '全部状态',
        enabledOnly: '仅已启用',
        disabledOnly: '仅已停用',
        projectFilter: '项目筛选',
        stateFilter: '启用状态',
        total: '监控任务',
        enabledCount: '已启用',
        runningCount: '运行中',
        recentNewCount: '最近新增',
        project: '项目',
        monitor: '监控',
        rootDomain: '根域名',
        provider: '数据源',
        period: '周期',
        state: '状态',
        lastRun: '上次运行',
        nextRun: '下次运行',
        recentNew: '新增',
        lastError: '最近错误',
        actions: '操作',
        refresh: '刷新',
        addMonitor: '新建监控',
        edit: '编辑',
        delete: '删除',
        runNow: '立即运行',
        history: '运行历史',
        loading: '正在加载监控任务…',
        empty: '当前筛选条件下没有资产监控任务。',
        noData: '—',
        previous: '上一页',
        next: '下一页',
        items: '项',
        page: '页',
        enabled: '已启用',
        disabled: '已停用',
        idle: '待运行',
        queued: '排队中',
        running: '运行中',
        success: '成功',
        partial: '部分完成',
        error: '失败',
        cancelled: '已取消',
        manual: '手动',
        scheduled: '定时',
        minutes: '{{count}} 分钟',
        hours: '{{count}} 小时',
        days: '{{count}} 天',
        editorCreate: '新建资产监控',
        editorEdit: '编辑资产监控',
        monitorName: '监控名称',
        monitorNamePlaceholder: '例如：快手公网资产',
        chooseProject: '请选择项目',
        rootDomainPlaceholder: '例如：kuaishou.com',
        providerHint: '当前版本使用 Quake 搜索并将新发现写入所选项目。',
        intervalMinutes: '检查周期（分钟）',
        intervalHint: '最短 60 分钟，默认每天运行一次。',
        maxResults: '单次结果上限',
        enableAfterSave: '保存后启用定时监控',
        cancel: '取消',
        save: '保存',
        saving: '保存中…',
        nameRequired: '请输入监控名称。',
        projectRequired: '请选择项目。',
        domainInvalid: '请输入不含协议、路径和通配符的有效根域名。',
        intervalInvalid: '周期必须是 60 到 10080 之间的整数分钟。',
        maxResultsInvalid: '结果上限必须是 1 到 1000 之间的整数。',
        requestFailed: '请求失败，请稍后重试。',
        projectLoadFailed: '项目列表加载失败，请刷新后重试。',
        saved: '资产监控已保存。',
        runAccepted: '已提交一次资产发现任务。',
        toggled: '监控状态已更新。',
        deleted: '资产监控已删除。',
        deleteConfirm: '删除监控“{{name}}”？已有运行历史将按服务端策略处理。',
        historyTitle: '运行历史：{{name}}',
        close: '关闭',
        trigger: '触发方式',
        startedAt: '开始时间',
        finishedAt: '完成时间',
        seenCount: '发现',
        newCount: '新增',
        updatedCount: '更新',
        skippedCount: '跳过',
        conflictCount: '冲突',
        runError: '错误',
        historyEmpty: '暂无运行记录。',
        historyLoading: '正在加载运行历史…',
        viewNewAssets: '查看新增资产',
        newAssetsTitle: '本次新增资产',
        newAssetsLoading: '正在加载新增资产…',
        newAssetsEmpty: '本次运行没有新增资产。',
        assetTarget: '资产',
        assetType: '类型',
        assetTitle: '标题',
        discoveredAt: '发现时间',
        noProjects: '没有可用项目，请先创建项目。',
        unknownProject: '未知项目',
        autoRefresh: '自动刷新',
    };

    let root = null;
    let page = null;
    let bound = false;
    let timer = null;
    let listController = null;
    let projectsController = null;
    let historyController = null;
    let assetsController = null;
    let sequence = 0;
    let projectSequence = 0;
    let historySequence = 0;
    let assetsSequence = 0;
    let focusReturn = null;
    let projectsLoaded = false;
    let projects = [];
    let projectNames = new Map();
    let monitors = new Map();
    let visibleItems = [];
    let lastSummary = {};
    let state = { page: 1, projectId: '', enabled: '' };
    let total = 0;

    const escapeHTML = value => String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[ch]);

    function interpolate(value, opts) {
        return String(value == null ? '' : value).replace(/\{\{(\w+)\}\}/g, (_match, key) => (
            opts && Object.prototype.hasOwnProperty.call(opts, key) ? String(opts[key]) : ''
        ));
    }

    function t(key, opts) {
        const fullKey = 'assetMonitor.' + key;
        const translated = typeof window !== 'undefined' && typeof window.t === 'function'
            ? window.t(fullKey, opts || {})
            : '';
        if (translated && translated !== fullKey) return translated;
        return interpolate(words[key] || key, opts);
    }

    function el(name) {
        return typeof document === 'undefined' ? null : document.getElementById('asset-monitor-' + name);
    }

    function active() {
        page = page || (typeof document !== 'undefined' ? document.getElementById('page-asset-monitor') : null);
        return !!root && (!page || !page.classList || page.classList.contains('active'));
    }

    function cleanID(value) {
        const id = String(value == null ? '' : value).trim();
        return /^[A-Za-z0-9:_-]{1,160}$/.test(id) ? id : '';
    }

    function finiteInt(value, fallback) {
        const number = Number(value);
        return Number.isFinite(number) ? Math.trunc(number) : fallback;
    }

    function boundedCount(value) {
        return Math.max(0, finiteInt(value, 0));
    }

    function formatCount(value) {
        try {
            return boundedCount(value).toLocaleString(typeof window !== 'undefined' ? window.__locale : undefined);
        } catch (_) {
            return String(boundedCount(value));
        }
    }

    function formatDate(value) {
        if (!value) return t('noData');
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return t('noData');
        try {
            return date.toLocaleString(typeof window !== 'undefined' ? window.__locale : undefined);
        } catch (_) {
            return date.toLocaleString();
        }
    }

    function normalizeRootDomain(value) {
        let raw = String(value == null ? '' : value).trim().toLowerCase();
        raw = raw.replace(/\.+$/, '');
        if (!raw || raw.length > 253 || /[\s/?#@*\\:[\]]/.test(raw)) return '';
        try {
            const parsed = new URL('https://' + raw);
            const host = parsed.hostname.toLowerCase().replace(/\.+$/, '');
            if (!host || parsed.host !== parsed.hostname || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
            const labels = host.split('.');
            if (labels.length < 2 || labels.some(label => (
                !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
            ))) return '';
            return host;
        } catch (_) {
            return '';
        }
    }

    function intervalFromCron(value) {
        const cron = String(value || '').trim();
        let match = cron.match(/^\*\/(\d+) \* \* \* \*$/);
        if (match) return finiteInt(match[1], 0);
        match = cron.match(/^0 \*\/(\d+) \* \* \*$/);
        if (match) return finiteInt(match[1], 0) * 60;
        if (/^\d+ \d+ \* \* \*$/.test(cron)) return 1440;
        return 0;
    }

    function normalizeMonitor(value) {
        const item = value && typeof value === 'object' ? value : {};
        const latestRun = item.latest_run && typeof item.latest_run === 'object'
            ? item.latest_run
            : (item.last_run && typeof item.last_run === 'object' ? item.last_run : {});
        const interval = finiteInt(
            item.interval_minutes != null ? item.interval_minutes : intervalFromCron(item.cron_expr),
            0,
        );
        return {
            id: cleanID(item.id),
            project_id: cleanID(item.project_id),
            project_name: String(item.project_name || ''),
            name: String(item.name || ''),
            root_domain: String(item.root_domain || ''),
            provider: String(item.provider || 'quake'),
            interval_minutes: interval,
            cron_expr: String(item.cron_expr || ''),
            max_results: finiteInt(item.max_results, DEFAULT_MAX_RESULTS),
            enabled: item.enabled === true,
            next_run_at: item.next_run_at || '',
            last_run_at: item.last_run_at || latestRun.finished_at || latestRun.started_at || '',
            last_status: String(item.last_status || latestRun.status || (item.enabled === false ? 'disabled' : 'idle')).toLowerCase(),
            last_error: String(item.last_error || latestRun.error || ''),
            recent_new_count: boundedCount(
                item.recent_new_count != null
                    ? item.recent_new_count
                    : (item.last_new_count != null ? item.last_new_count : latestRun.new_count),
            ),
            latest_run: latestRun,
        };
    }

    function normalizeRun(value) {
        const run = value && typeof value === 'object' ? value : {};
        return {
            id: cleanID(run.id),
            monitor_id: cleanID(run.monitor_id),
            trigger: String(run.trigger || '').toLowerCase(),
            status: String(run.status || '').toLowerCase(),
            started_at: run.started_at || '',
            finished_at: run.finished_at || '',
            seen_count: boundedCount(run.seen_count),
            new_count: boundedCount(run.new_count),
            updated_count: boundedCount(run.updated_count),
            skipped_count: boundedCount(run.skipped_count),
            conflict_count: boundedCount(run.conflict_count),
            error: String(run.error || ''),
        };
    }

    function intervalLabel(minutes, cronExpr) {
        const value = finiteInt(minutes, 0);
        if (value > 0 && value % 1440 === 0) return t('days', { count: value / 1440 });
        if (value > 0 && value % 60 === 0) return t('hours', { count: value / 60 });
        if (value > 0) return t('minutes', { count: value });
        return String(cronExpr || t('noData'));
    }

    function safeStatus(value, enabled) {
        if (enabled === false) return 'disabled';
        const status = String(value || '').toLowerCase();
        return STATUS_VALUES.has(status) ? status : 'idle';
    }

    function statusLabel(value, enabled) {
        return t(safeStatus(value, enabled));
    }

    function runStatus(value) {
        const status = String(value || '').toLowerCase();
        return RUN_STATUS_VALUES.has(status) ? status : 'queued';
    }

    function parseListResponse(payload) {
        const source = payload && typeof payload === 'object' && !Array.isArray(payload) && payload.data
            && typeof payload.data === 'object' ? payload.data : payload;
        if (Array.isArray(source)) {
            return { items: source, total: source.length, summary: {} };
        }
        const object = source && typeof source === 'object' ? source : {};
        const items = Array.isArray(object.items)
            ? object.items
            : (Array.isArray(object.monitors) ? object.monitors : []);
        return {
            items,
            total: Math.max(0, finiteInt(object.total, items.length)),
            summary: object.summary && typeof object.summary === 'object'
                ? object.summary
                : (object.stats && typeof object.stats === 'object' ? object.stats : {}),
        };
    }

    function parseRunsResponse(payload) {
        const source = payload && typeof payload === 'object' && !Array.isArray(payload) && payload.data
            && typeof payload.data === 'object' ? payload.data : payload;
        if (Array.isArray(source)) return source;
        if (!source || typeof source !== 'object') return [];
        if (Array.isArray(source.items)) return source.items;
        return Array.isArray(source.runs) ? source.runs : [];
    }

    function parseAssetsResponse(payload) {
        const source = payload && typeof payload === 'object' && !Array.isArray(payload) && payload.data
            && typeof payload.data === 'object' ? payload.data : payload;
        if (Array.isArray(source)) return source;
        if (!source || typeof source !== 'object') return [];
        if (Array.isArray(source.items)) return source.items;
        return Array.isArray(source.assets) ? source.assets : [];
    }

    async function request(path, options) {
        const response = await apiFetch(API_ROOT + path, options || {});
        let payload = {};
        try {
            payload = await response.json();
        } catch (_) {
            payload = {};
        }
        if (!response.ok) {
            const raw = payload && (payload.error || payload.message);
            const message = typeof raw === 'string' && raw.trim() ? raw.trim().slice(0, 500) : t('requestFailed');
            const error = new Error(message);
            error.status = response.status;
            throw error;
        }
        return payload;
    }

    function showError(message) {
        const target = el('error');
        if (!target) return;
        target.textContent = message || '';
        target.hidden = !message;
    }

    function notify(message, type) {
        if (typeof showNotification === 'function') {
            showNotification(message, type || 'success');
        } else if (typeof showToast === 'function') {
            showToast(message, type || 'success');
        }
    }

    function canAll(permissions) {
        if (typeof hasPermission !== 'function') return true;
        return permissions.every(permission => hasPermission(permission));
    }

    function requireAll(permissions) {
        if (canAll(permissions)) return true;
        const missing = typeof hasPermission === 'function'
            ? permissions.find(permission => !hasPermission(permission))
            : '';
        if (missing && typeof requirePermission === 'function') return requirePermission(missing);
        return false;
    }

    function projectFromHash() {
        if (typeof window === 'undefined') return '';
        const hash = String(window.location && window.location.hash || '').replace(/^#/, '');
        const parts = hash.split('?');
        if (parts[0] !== 'asset-monitor' || parts.length < 2) return '';
        return cleanID(new URLSearchParams(parts.slice(1).join('?')).get('project'));
    }

    function updateProjectHash() {
        if (typeof window === 'undefined' || !window.history || typeof window.history.replaceState !== 'function') return;
        const suffix = state.projectId ? '?project=' + encodeURIComponent(state.projectId) : '';
        window.history.replaceState(null, '', '#asset-monitor' + suffix);
    }

    function queryString(value) {
        const current = value || state;
        const params = new URLSearchParams();
        params.set('limit', String(PAGE_SIZE));
        params.set('offset', String(Math.max(0, (Math.max(1, finiteInt(current.page, 1)) - 1) * PAGE_SIZE)));
        const projectId = cleanID(current.projectId);
        if (projectId) params.set('project_id', projectId);
        if (current.enabled === 'true' || current.enabled === 'false') params.set('enabled', current.enabled);
        return params.toString();
    }

    function projectOptions(includeAll) {
        const options = [];
        if (includeAll) options.push('<option value="">' + escapeHTML(t('allProjects')) + '</option>');
        else options.push('<option value="" disabled>' + escapeHTML(t('chooseProject')) + '</option>');
        projects.forEach(project => {
            options.push(
                '<option value="' + escapeHTML(project.id) + '">' + escapeHTML(project.name || project.id) + '</option>',
            );
        });
        return options.join('');
    }

    function renderProjectOptions() {
        const filter = el('project-filter');
        const editor = el('editor-project');
        if (filter) {
            const current = state.projectId || filter.value || '';
            filter.innerHTML = projectOptions(true);
            filter.value = current;
            if (current && filter.value !== current) filter.value = '';
        }
        if (editor) {
            const current = editor.value || '';
            editor.innerHTML = projectOptions(false);
            editor.value = current;
        }
    }

    function layout() {
        if (!root) return;
        root.innerHTML = [
            '<div class="am-topbar" aria-label="' + escapeHTML(t('autoRefresh')) + '">',
            '<label class="am-filter"><span>' + escapeHTML(t('projectFilter')) + '</span><select id="asset-monitor-project-filter" aria-label="' + escapeHTML(t('projectFilter')) + '">' + projectOptions(true) + '</select></label>',
            '<label class="am-filter"><span>' + escapeHTML(t('stateFilter')) + '</span><select id="asset-monitor-enabled-filter" aria-label="' + escapeHTML(t('stateFilter')) + '">',
            '<option value="">' + escapeHTML(t('allStates')) + '</option><option value="true">' + escapeHTML(t('enabledOnly')) + '</option><option value="false">' + escapeHTML(t('disabledOnly')) + '</option></select></label>',
            '<div id="asset-monitor-summary" class="am-summary" aria-live="polite"></div>',
            '</div>',
            '<div id="asset-monitor-error" class="am-alert" role="alert" hidden></div>',
            '<div class="am-table-wrap">',
            '<table class="am-table"><thead><tr>',
            ['project', 'monitor', 'rootDomain', 'period', 'state', 'lastRun', 'recentNew', 'lastError', 'actions']
                .map(key => '<th scope="col">' + escapeHTML(t(key)) + '</th>').join(''),
            '</tr></thead><tbody id="asset-monitor-list"></tbody></table>',
            '<p id="asset-monitor-empty" class="am-empty">' + escapeHTML(t('loading')) + '</p>',
            '</div>',
            '<footer class="am-pagination"><span id="asset-monitor-count"></span><button id="asset-monitor-prev" type="button" class="btn-secondary btn-small">' + escapeHTML(t('previous')) + '</button><span id="asset-monitor-page-number"></span><button id="asset-monitor-next" type="button" class="btn-secondary btn-small">' + escapeHTML(t('next')) + '</button></footer>',
            '<dialog id="asset-monitor-editor-dialog" class="am-dialog am-editor-dialog" aria-labelledby="asset-monitor-editor-title">',
            '<form id="asset-monitor-editor-form" novalidate>',
            '<header><div><h2 id="asset-monitor-editor-title">' + escapeHTML(t('editorCreate')) + '</h2><p>' + escapeHTML(t('providerHint')) + '</p></div><button type="button" class="am-dialog-close" data-am-close="editor" aria-label="' + escapeHTML(t('close')) + '">×</button></header>',
            '<div class="am-dialog-body">',
            '<input id="asset-monitor-editor-id" type="hidden">',
            '<div id="asset-monitor-editor-error" class="am-alert" role="alert" hidden></div>',
            '<div class="am-form-grid">',
            '<label><span>' + escapeHTML(t('project')) + '</span><select id="asset-monitor-editor-project" required>' + projectOptions(false) + '</select></label>',
            '<label><span>' + escapeHTML(t('monitorName')) + '</span><input id="asset-monitor-editor-name" type="text" maxlength="120" required placeholder="' + escapeHTML(t('monitorNamePlaceholder')) + '"></label>',
            '<label><span>' + escapeHTML(t('rootDomain')) + '</span><input id="asset-monitor-editor-domain" type="text" maxlength="253" autocapitalize="none" spellcheck="false" required placeholder="' + escapeHTML(t('rootDomainPlaceholder')) + '"></label>',
            '<label><span>' + escapeHTML(t('provider')) + '</span><input value="Quake" disabled aria-label="' + escapeHTML(t('provider')) + '"></label>',
            '<label><span>' + escapeHTML(t('intervalMinutes')) + '</span><input id="asset-monitor-editor-interval" type="number" min="' + MIN_INTERVAL_MINUTES + '" max="' + MAX_INTERVAL_MINUTES + '" step="1" value="' + DEFAULT_INTERVAL_MINUTES + '" required><small>' + escapeHTML(t('intervalHint')) + '</small></label>',
            '<label><span>' + escapeHTML(t('maxResults')) + '</span><input id="asset-monitor-editor-max-results" type="number" min="1" max="' + MAX_RESULTS + '" step="1" value="' + DEFAULT_MAX_RESULTS + '" required></label>',
            '</div>',
            '<label class="am-editor-enabled"><input id="asset-monitor-editor-enabled" type="checkbox" checked><span>' + escapeHTML(t('enableAfterSave')) + '</span></label>',
            '</div>',
            '<footer><button type="button" class="btn-secondary" data-am-close="editor">' + escapeHTML(t('cancel')) + '</button><button id="asset-monitor-editor-save" type="submit" class="btn-primary">' + escapeHTML(t('save')) + '</button></footer>',
            '</form></dialog>',
            '<dialog id="asset-monitor-history-dialog" class="am-dialog am-history-dialog" aria-labelledby="asset-monitor-history-title">',
            '<header><h2 id="asset-monitor-history-title">' + escapeHTML(t('history')) + '</h2><button type="button" class="am-dialog-close" data-am-close="history" aria-label="' + escapeHTML(t('close')) + '">×</button></header>',
            '<div id="asset-monitor-history-body" class="am-history-body"></div>',
            '<section id="asset-monitor-run-assets" class="am-run-assets" hidden></section>',
            '<footer><button type="button" class="btn-secondary" data-am-close="history">' + escapeHTML(t('close')) + '</button></footer>',
            '</dialog>',
        ].join('');

        el('project-filter').value = state.projectId;
        el('enabled-filter').value = state.enabled;
        el('project-filter').addEventListener('change', event => {
            state.projectId = cleanID(event.target.value);
            state.page = 1;
            updateProjectHash();
            refresh();
        });
        el('enabled-filter').addEventListener('change', event => {
            state.enabled = event.target.value === 'true' || event.target.value === 'false' ? event.target.value : '';
            state.page = 1;
            refresh();
        });
        el('prev').addEventListener('click', () => {
            if (state.page > 1) {
                state.page -= 1;
                refresh();
            }
        });
        el('next').addEventListener('click', () => {
            state.page += 1;
            refresh();
        });
        el('editor-form').addEventListener('submit', event => {
            event.preventDefault();
            if (typeof window !== 'undefined' && typeof window.saveAssetMonitor === 'function') {
                void window.saveAssetMonitor();
            } else {
                void save();
            }
        });
        root.addEventListener('click', handleClick);
        root.addEventListener('change', handleChange);
        ['editor-dialog', 'history-dialog'].forEach(name => {
            const dialog = el(name);
            if (!dialog) return;
            dialog.addEventListener('cancel', event => {
                event.preventDefault();
                closeDialog(name === 'editor-dialog' ? 'editor' : 'history');
            });
            dialog.addEventListener('click', event => {
                if (event.target === dialog) closeDialog(name === 'editor-dialog' ? 'editor' : 'history');
            });
            dialog.addEventListener('close', () => {
                if (name === 'history-dialog') {
                    historySequence += 1;
                    assetsSequence += 1;
                    if (historyController) historyController.abort();
                    if (assetsController) assetsController.abort();
                    historyController = null;
                    assetsController = null;
                }
                if (focusReturn && focusReturn.isConnected && typeof focusReturn.focus === 'function') focusReturn.focus();
                focusReturn = null;
            });
        });
        bound = true;
        renderSummary(lastSummary);
        renderList(visibleItems);
        renderProjectOptions();
        if (typeof applyRBACToUI === 'function') applyRBACToUI(root);
    }

    function handleClick(event) {
        const close = event.target && event.target.closest ? event.target.closest('[data-am-close]') : null;
        if (close) {
            closeDialog(close.dataset.amClose);
            return;
        }
        const action = event.target && event.target.closest ? event.target.closest('[data-am-action]') : null;
        if (!action) return;
        const id = cleanID(action.dataset.monitorId);
        const kind = action.dataset.amAction;
        if (kind === 'edit') {
            if (typeof window !== 'undefined' && typeof window.openAssetMonitorEditor === 'function') void window.openAssetMonitorEditor(id, action);
            else void openEditor(id, action);
        } else if (kind === 'run') {
            if (typeof window !== 'undefined' && typeof window.runAssetMonitorNow === 'function') void window.runAssetMonitorNow(id, action);
            else void runNow(id, action);
        } else if (kind === 'history') {
            void openHistory(id, action);
        } else if (kind === 'delete') {
            if (typeof window !== 'undefined' && typeof window.deleteAssetMonitor === 'function') void window.deleteAssetMonitor(id, action);
            else void remove(id, action);
        } else if (kind === 'run-assets') {
            void loadRunAssets(
                cleanID(action.dataset.monitorId),
                cleanID(action.dataset.runId),
                action,
            );
        }
    }

    function handleChange(event) {
        const input = event.target && event.target.closest ? event.target.closest('[data-am-enabled]') : null;
        if (!input) return;
        const id = cleanID(input.dataset.monitorId);
        if (typeof window !== 'undefined' && typeof window.toggleAssetMonitorEnabled === 'function') {
            void window.toggleAssetMonitorEnabled(id, input.checked, input);
        } else {
            void toggleEnabled(id, input.checked, input);
        }
    }

    function renderSummary(summary) {
        const target = el('summary');
        if (!target) return;
        const data = summary && typeof summary === 'object' ? summary : {};
        const enabledFallback = visibleItems.filter(item => item.enabled).length;
        const runningFallback = visibleItems.filter(item => ['queued', 'running'].includes(safeStatus(item.last_status, item.enabled))).length;
        const newFallback = visibleItems.reduce((sum, item) => sum + item.recent_new_count, 0);
        const values = [
            ['total', data.total != null ? data.total : total],
            ['enabledCount', data.enabled != null ? data.enabled : (data.enabled_count != null ? data.enabled_count : enabledFallback)],
            ['runningCount', data.running != null ? data.running : (data.running_count != null ? data.running_count : runningFallback)],
            ['recentNewCount', data.recent_new_count != null ? data.recent_new_count : (data.new_count != null ? data.new_count : newFallback)],
        ];
        target.innerHTML = values.map(item => (
            '<span class="am-summary-chip"><small>' + escapeHTML(t(item[0])) + '</small><strong>' + escapeHTML(formatCount(item[1])) + '</strong></span>'
        )).join('');
    }

    function rowHTML(raw, names) {
        const item = normalizeMonitor(raw);
        const nameMap = names instanceof Map ? names : projectNames;
        const projectName = item.project_name || nameMap.get(item.project_id) || item.project_id || t('unknownProject');
        const status = safeStatus(item.last_status, item.enabled);
        const running = status === 'queued' || status === 'running';
        const error = item.last_error.trim();
        const id = escapeHTML(item.id);
        const enableControl = item.enabled
            ? '<label class="am-switch" data-require-permissions="asset:write project:write"><input type="checkbox" data-am-enabled data-monitor-id="' + id + '" checked aria-label="' + escapeHTML(t('enabled')) + '"><span aria-hidden="true"></span></label>'
            : '<label class="am-switch" data-require-permissions="asset:write project:write"><input type="checkbox" data-am-enabled data-monitor-id="' + id + '" aria-label="' + escapeHTML(t('disabled')) + '"><span aria-hidden="true"></span></label>';
        return [
            '<tr>',
            '<td><span class="am-project">' + escapeHTML(projectName) + '</span></td>',
            '<td><strong class="am-monitor-name">' + escapeHTML(item.name || t('noData')) + '</strong><small>' + escapeHTML(item.provider || 'quake') + '</small></td>',
            '<td><code class="am-domain">' + escapeHTML(item.root_domain || t('noData')) + '</code></td>',
            '<td><span>' + escapeHTML(intervalLabel(item.interval_minutes, item.cron_expr)) + '</span><small>' + escapeHTML(t('nextRun')) + '：' + escapeHTML(formatDate(item.next_run_at)) + '</small></td>',
            '<td><div class="am-state-cell"><span class="am-status is-' + status + '">' + escapeHTML(statusLabel(status, item.enabled)) + '</span>' + enableControl + '</div></td>',
            '<td><span>' + escapeHTML(formatDate(item.last_run_at)) + '</span></td>',
            '<td><button type="button" class="am-new-count" data-am-action="history" data-monitor-id="' + id + '" aria-label="' + escapeHTML(t('history')) + '">' + escapeHTML(formatCount(item.recent_new_count)) + '</button></td>',
            '<td>' + (error ? '<span class="am-error-text">' + escapeHTML(error) + '</span>' : '<span class="am-muted">' + escapeHTML(t('noData')) + '</span>') + '</td>',
            '<td><div class="am-actions">',
            '<button type="button" class="btn-secondary btn-small" data-am-action="history" data-monitor-id="' + id + '">' + escapeHTML(t('history')) + '</button>',
            '<button type="button" class="btn-secondary btn-small" data-am-action="run" data-monitor-id="' + id + '" data-require-permissions="asset:write project:write fofa:execute"' + (running ? ' disabled' : '') + '>' + escapeHTML(running ? t('running') : t('runNow')) + '</button>',
            '<button type="button" class="btn-secondary btn-small" data-am-action="edit" data-monitor-id="' + id + '" data-require-permissions="asset:write project:write">' + escapeHTML(t('edit')) + '</button>',
            '<button type="button" class="btn-danger btn-small" data-am-action="delete" data-monitor-id="' + id + '" data-require-permissions="asset:delete project:write">' + escapeHTML(t('delete')) + '</button>',
            '</div></td>',
            '</tr>',
        ].join('');
    }

    function renderList(items) {
        const list = el('list');
        const empty = el('empty');
        if (!list || !empty) return;
        const normalized = Array.isArray(items) ? items.map(normalizeMonitor).filter(item => item.id) : [];
        list.innerHTML = normalized.map(item => rowHTML(item)).join('');
        empty.textContent = t('empty');
        empty.hidden = normalized.length > 0;
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const count = el('count');
        const pageNumber = el('page-number');
        if (count) count.textContent = formatCount(total) + ' ' + t('items');
        if (pageNumber) pageNumber.textContent = state.page + ' / ' + totalPages + ' ' + t('page');
        if (el('prev')) el('prev').disabled = state.page <= 1;
        if (el('next')) el('next').disabled = state.page >= totalPages;
        if (typeof applyRBACToUI === 'function') applyRBACToUI(root);
    }

    function scheduleRefresh(delay) {
        clearTimeout(timer);
        timer = null;
        if (!active()) return;
        timer = setTimeout(refresh, delay);
    }

    async function refresh() {
        if (!active()) {
            clearTimeout(timer);
            timer = null;
            if (listController) listController.abort();
            return false;
        }
        clearTimeout(timer);
        timer = null;
        if (listController) listController.abort();
        listController = new AbortController();
        const currentSequence = ++sequence;
        const refreshButton = typeof document !== 'undefined' ? document.getElementById('asset-monitor-refresh') : null;
        if (refreshButton) refreshButton.setAttribute('aria-busy', 'true');
        try {
            const payload = await request('?' + queryString(state), { signal: listController.signal });
            if (currentSequence !== sequence || !active()) return false;
            const parsed = parseListResponse(payload);
            visibleItems = parsed.items.map(normalizeMonitor).filter(item => item.id);
            monitors = new Map(visibleItems.map(item => [item.id, item]));
            total = parsed.total;
            lastSummary = parsed.summary;
            if (!visibleItems.length && total > 0 && state.page > 1) {
                state.page -= 1;
                return refresh();
            }
            showError('');
            renderSummary(lastSummary);
            renderList(visibleItems);
            const isRunning = visibleItems.some(item => {
                const status = safeStatus(item.last_status, item.enabled);
                return status === 'queued' || status === 'running';
            });
            scheduleRefresh(isRunning ? POLL_RUNNING_MS : POLL_IDLE_MS);
            return true;
        } catch (error) {
            if (currentSequence !== sequence || error.name === 'AbortError' || !active()) return false;
            showError(error.message || t('requestFailed'));
            scheduleRefresh(POLL_IDLE_MS);
            return false;
        } finally {
            if (currentSequence === sequence && refreshButton) refreshButton.removeAttribute('aria-busy');
        }
    }

    async function loadProjects(force) {
        if (projectsLoaded && !force) return projects;
        if (projectsController) projectsController.abort();
        projectsController = new AbortController();
        const currentSequence = ++projectSequence;
        try {
            const response = await apiFetch('/api/projects?status=active&limit=500&offset=0', {
                signal: projectsController.signal,
            });
            let data = {};
            try {
                data = await response.json();
            } catch (_) {
                data = {};
            }
            if (!response.ok) throw new Error(t('projectLoadFailed'));
            if (currentSequence !== projectSequence) return projects;
            const source = Array.isArray(data) ? data : (Array.isArray(data.projects) ? data.projects : (Array.isArray(data.items) ? data.items : []));
            projects = source.map(item => ({
                id: cleanID(item && item.id),
                name: String(item && item.name || ''),
            })).filter(item => item.id);
            projectNames = new Map(projects.map(item => [item.id, item.name || item.id]));
            projectsLoaded = true;
            renderProjectOptions();
            renderList(visibleItems);
            return projects;
        } catch (error) {
            if (error.name !== 'AbortError' && active()) showError(error.message || t('projectLoadFailed'));
            return projects;
        }
    }

    function showDialog(dialog) {
        if (!dialog) return;
        if (typeof dialog.showModal === 'function' && !dialog.open) dialog.showModal();
        else dialog.setAttribute('open', '');
    }

    function closeDialog(kind) {
        const name = kind === 'history' ? 'history-dialog' : 'editor-dialog';
        const dialog = el(name);
        if (!dialog) return;
        if (dialog.open && typeof dialog.close === 'function') dialog.close();
        else dialog.removeAttribute('open');
    }

    function setEditorError(message) {
        const target = el('editor-error');
        if (!target) return;
        target.textContent = message || '';
        target.hidden = !message;
    }

    async function openEditor(id, button) {
        if (!canAll(['asset:write', 'project:write'])) {
            requireAll(['asset:write', 'project:write']);
            return false;
        }
        await loadProjects(false);
        const monitorId = cleanID(id);
        const item = monitorId ? monitors.get(monitorId) : null;
        if (monitorId && !item) return false;
        if (!projects.length && !item) {
            showError(t('noProjects'));
            return false;
        }
        focusReturn = button || (typeof document !== 'undefined' ? document.activeElement : null);
        el('editor-form').reset();
        renderProjectOptions();
        el('editor-id').value = item ? item.id : '';
        el('editor-title').textContent = item ? t('editorEdit') : t('editorCreate');
        el('editor-project').value = item ? item.project_id : (state.projectId || '');
        el('editor-project').disabled = !!item;
        if (!el('editor-project').value && projects.length) el('editor-project').value = projects[0].id;
        el('editor-name').value = item ? item.name : '';
        el('editor-domain').value = item ? item.root_domain : '';
        el('editor-interval').value = String(item && item.interval_minutes > 0 ? item.interval_minutes : DEFAULT_INTERVAL_MINUTES);
        el('editor-max-results').value = String(item && item.max_results > 0 ? item.max_results : DEFAULT_MAX_RESULTS);
        el('editor-enabled').checked = item ? item.enabled : true;
        setEditorError('');
        showDialog(el('editor-dialog'));
        if (el('editor-name') && typeof el('editor-name').focus === 'function') el('editor-name').focus();
        return true;
    }

    function editorPayload() {
        const projectId = cleanID(el('editor-project').value);
        const name = String(el('editor-name').value || '').trim();
        const rootDomain = normalizeRootDomain(el('editor-domain').value);
        const interval = finiteInt(el('editor-interval').value, 0);
        const maxResults = finiteInt(el('editor-max-results').value, 0);
        if (!projectId) throw new Error(t('projectRequired'));
        if (!name) throw new Error(t('nameRequired'));
        if (!rootDomain) throw new Error(t('domainInvalid'));
        if (interval < MIN_INTERVAL_MINUTES || interval > MAX_INTERVAL_MINUTES || String(interval) !== String(el('editor-interval').value).trim()) {
            throw new Error(t('intervalInvalid'));
        }
        if (maxResults < 1 || maxResults > MAX_RESULTS || String(maxResults) !== String(el('editor-max-results').value).trim()) {
            throw new Error(t('maxResultsInvalid'));
        }
        return {
            project_id: projectId,
            name,
            root_domain: rootDomain,
            provider: 'quake',
            enabled: el('editor-enabled').checked === true,
            interval_minutes: interval,
            max_results: maxResults,
        };
    }

    async function save() {
        if (!canAll(['asset:write', 'project:write'])) {
            requireAll(['asset:write', 'project:write']);
            return false;
        }
        let payload;
        try {
            payload = editorPayload();
        } catch (error) {
            setEditorError(error.message);
            return false;
        }
        const id = cleanID(el('editor-id').value);
        const button = el('editor-save');
        if (button) {
            button.disabled = true;
            button.textContent = t('saving');
        }
        try {
            await request(id ? '/' + encodeURIComponent(id) : '', {
                method: id ? 'PATCH' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            setEditorError('');
            closeDialog('editor');
            notify(t('saved'), 'success');
            await refresh();
            return true;
        } catch (error) {
            setEditorError(error.message || t('requestFailed'));
            return false;
        } finally {
            if (button && button.isConnected) {
                button.disabled = false;
                button.textContent = t('save');
            }
        }
    }

    async function toggleEnabled(id, enabled, input) {
        const monitorId = cleanID(id);
        if (!monitorId || !canAll(['asset:write', 'project:write'])) {
            if (input) input.checked = !enabled;
            requireAll(['asset:write', 'project:write']);
            return false;
        }
        if (input) input.disabled = true;
        try {
            await request('/' + encodeURIComponent(monitorId), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: enabled === true }),
            });
            notify(t('toggled'), 'success');
            await refresh();
            return true;
        } catch (error) {
            if (input && input.isConnected) input.checked = !enabled;
            showError(error.message || t('requestFailed'));
            return false;
        } finally {
            if (input && input.isConnected) input.disabled = false;
        }
    }

    async function runNow(id, button) {
        const monitorId = cleanID(id);
        if (!monitorId || !canAll(['asset:write', 'project:write', 'fofa:execute'])) {
            requireAll(['asset:write', 'project:write', 'fofa:execute']);
            return false;
        }
        if (button) button.disabled = true;
        try {
            await request('/' + encodeURIComponent(monitorId) + '/run', { method: 'POST' });
            notify(t('runAccepted'), 'success');
            await refresh();
            scheduleRefresh(1200);
            return true;
        } catch (error) {
            showError(error.message || t('requestFailed'));
            return false;
        } finally {
            if (button && button.isConnected) button.disabled = false;
        }
    }

    async function confirmDelete(message) {
        if (typeof appConfirm === 'function') return appConfirm(message);
        if (typeof window !== 'undefined' && typeof window.confirm === 'function') return window.confirm(message);
        return false;
    }

    async function remove(id, button) {
        const monitorId = cleanID(id);
        const item = monitors.get(monitorId);
        if (!monitorId || !item || !canAll(['asset:delete', 'project:write'])) {
            requireAll(['asset:delete', 'project:write']);
            return false;
        }
        if (!await confirmDelete(t('deleteConfirm', { name: item.name || item.root_domain }))) return false;
        if (button) button.disabled = true;
        try {
            await request('/' + encodeURIComponent(monitorId), { method: 'DELETE' });
            notify(t('deleted'), 'success');
            if (visibleItems.length === 1 && state.page > 1) state.page -= 1;
            await refresh();
            return true;
        } catch (error) {
            showError(error.message || t('requestFailed'));
            return false;
        } finally {
            if (button && button.isConnected) button.disabled = false;
        }
    }

    function historyHTML(values, monitorId) {
        const runs = Array.isArray(values) ? values.map(normalizeRun).filter(run => run.id) : [];
        if (!runs.length) return '<p class="am-history-empty">' + escapeHTML(t('historyEmpty')) + '</p>';
        return [
            '<div class="am-history-table-wrap"><table class="am-history-table"><thead><tr>',
            ['state', 'trigger', 'startedAt', 'finishedAt', 'seenCount', 'newCount', 'updatedCount', 'skippedCount', 'conflictCount', 'runError']
                .map(key => '<th scope="col">' + escapeHTML(t(key)) + '</th>').join(''),
            '</tr></thead><tbody>',
            runs.map(run => {
                const status = runStatus(run.status);
                const trigger = run.trigger === 'manual' || run.trigger === 'scheduled' ? run.trigger : 'scheduled';
                const newValue = run.new_count > 0
                    ? '<button type="button" class="am-new-count" data-am-action="run-assets" data-monitor-id="' + escapeHTML(monitorId) + '" data-run-id="' + escapeHTML(run.id) + '">' + escapeHTML(formatCount(run.new_count)) + ' · ' + escapeHTML(t('viewNewAssets')) + '</button>'
                    : escapeHTML(formatCount(run.new_count));
                return [
                    '<tr>',
                    '<td><span class="am-status is-' + status + '">' + escapeHTML(t(status)) + '</span></td>',
                    '<td>' + escapeHTML(t(trigger)) + '</td>',
                    '<td>' + escapeHTML(formatDate(run.started_at)) + '</td>',
                    '<td>' + escapeHTML(formatDate(run.finished_at)) + '</td>',
                    '<td>' + escapeHTML(formatCount(run.seen_count)) + '</td>',
                    '<td>' + newValue + '</td>',
                    '<td>' + escapeHTML(formatCount(run.updated_count)) + '</td>',
                    '<td>' + escapeHTML(formatCount(run.skipped_count)) + '</td>',
                    '<td>' + escapeHTML(formatCount(run.conflict_count)) + '</td>',
                    '<td>' + (run.error ? '<span class="am-error-text">' + escapeHTML(run.error) + '</span>' : escapeHTML(t('noData'))) + '</td>',
                    '</tr>',
                ].join('');
            }).join(''),
            '</tbody></table></div>',
        ].join('');
    }

    async function openHistory(id, button) {
        const monitorId = cleanID(id);
        const item = monitors.get(monitorId);
        if (!monitorId || !item) return false;
        focusReturn = button || (typeof document !== 'undefined' ? document.activeElement : null);
        el('history-title').textContent = t('historyTitle', { name: item.name || item.root_domain });
        el('history-body').innerHTML = '<p class="am-history-empty">' + escapeHTML(t('historyLoading')) + '</p>';
        el('run-assets').hidden = true;
        el('run-assets').innerHTML = '';
        showDialog(el('history-dialog'));
        if (historyController) historyController.abort();
        historyController = new AbortController();
        const currentSequence = ++historySequence;
        try {
            const payload = await request(
                '/' + encodeURIComponent(monitorId) + '/runs?limit=' + RUN_HISTORY_LIMIT + '&offset=0',
                { signal: historyController.signal },
            );
            if (currentSequence !== historySequence) return false;
            el('history-body').innerHTML = historyHTML(parseRunsResponse(payload), monitorId);
            return true;
        } catch (error) {
            if (error.name === 'AbortError' || currentSequence !== historySequence) return false;
            el('history-body').innerHTML = '<div class="am-alert" role="alert">' + escapeHTML(error.message || t('requestFailed')) + '</div>';
            return false;
        }
    }

    function assetTarget(asset) {
        const value = asset && typeof asset === 'object' ? (asset.asset && typeof asset.asset === 'object' ? asset.asset : asset) : {};
        const base = String(value.target || value.domain || value.host || value.ip || value.url || value.value || '');
        const port = boundedCount(value.port);
        const withPort = base && port > 0 && !base.endsWith(':' + port) ? base + ':' + port : base;
        const protocol = String(value.protocol || '').trim().toLowerCase();
        return protocol && withPort && !withPort.includes('://') ? protocol + '://' + withPort : withPort;
    }

    function runAssetsHTML(values) {
        const items = Array.isArray(values) ? values : [];
        if (!items.length) return '<p class="am-history-empty">' + escapeHTML(t('newAssetsEmpty')) + '</p>';
        return [
            '<h3>' + escapeHTML(t('newAssetsTitle')) + '</h3>',
            '<div class="am-run-assets-table-wrap"><table class="am-history-table"><thead><tr>',
            ['assetTarget', 'assetType', 'assetTitle', 'discoveredAt'].map(key => '<th scope="col">' + escapeHTML(t(key)) + '</th>').join(''),
            '</tr></thead><tbody>',
            items.map(raw => {
                const item = raw && typeof raw === 'object' && raw.asset && typeof raw.asset === 'object' ? raw.asset : (raw || {});
                return [
                    '<tr><td><code>' + escapeHTML(assetTarget(raw) || t('noData')) + '</code></td>',
                    '<td>' + escapeHTML(item.type || item.asset_type || item.protocol || item.server || t('noData')) + '</td>',
                    '<td>' + escapeHTML(item.title || t('noData')) + '</td>',
                    '<td>' + escapeHTML(formatDate(raw.observed_at || raw.discovered_at || raw.created_at || item.observed_at || item.discovered_at || item.created_at)) + '</td></tr>',
                ].join('');
            }).join(''),
            '</tbody></table></div>',
        ].join('');
    }

    async function loadRunAssets(monitorIdValue, runIdValue, button) {
        const monitorId = cleanID(monitorIdValue);
        const runId = cleanID(runIdValue);
        if (!monitorId || !runId) return false;
        const target = el('run-assets');
        target.hidden = false;
        target.innerHTML = '<p class="am-history-empty">' + escapeHTML(t('newAssetsLoading')) + '</p>';
        if (button) button.disabled = true;
        if (assetsController) assetsController.abort();
        assetsController = new AbortController();
        const currentSequence = ++assetsSequence;
        try {
            const payload = await request(
                '/' + encodeURIComponent(monitorId) + '/runs/' + encodeURIComponent(runId) + '/assets?state=new&limit=100',
                { signal: assetsController.signal },
            );
            if (currentSequence !== assetsSequence) return false;
            target.innerHTML = runAssetsHTML(parseAssetsResponse(payload));
            if (typeof target.scrollIntoView === 'function') target.scrollIntoView({ block: 'nearest' });
            return true;
        } catch (error) {
            if (error.name === 'AbortError' || currentSequence !== assetsSequence) return false;
            target.innerHTML = '<div class="am-alert" role="alert">' + escapeHTML(error.message || t('requestFailed')) + '</div>';
            return false;
        } finally {
            if (button && button.isConnected) button.disabled = false;
        }
    }

    function init() {
        root = typeof document !== 'undefined' ? document.getElementById('asset-monitor-content') : null;
        if (!root) return;
        page = document.getElementById('page-asset-monitor') || (root.closest ? root.closest('.page') : null);
        state.projectId = projectFromHash() || state.projectId;
        if (!bound) layout();
        else {
            renderProjectOptions();
            renderSummary(lastSummary);
            renderList(visibleItems);
        }
        void loadProjects(false);
        void refresh();
    }

    function stop() {
        clearTimeout(timer);
        timer = null;
        sequence += 1;
        projectSequence += 1;
        historySequence += 1;
        assetsSequence += 1;
        [listController, projectsController, historyController, assetsController].forEach(controller => {
            if (controller) controller.abort();
        });
        listController = null;
        projectsController = null;
        historyController = null;
        assetsController = null;
        closeDialog('editor');
        closeDialog('history');
        focusReturn = null;
    }

    function rerenderLanguage() {
        if (!root || !bound) return;
        const wasActive = active();
        stop();
        root.innerHTML = '';
        bound = false;
        layout();
        if (wasActive) {
            void loadProjects(false);
            void refresh();
        }
    }

    return {
        init,
        stop,
        refresh,
        openEditor,
        save,
        toggleEnabled,
        runNow,
        remove,
        openHistory,
        loadRunAssets,
        escapeHTML,
        normalizeRootDomain,
        normalizeMonitor,
        normalizeRun,
        intervalLabel,
        statusLabel,
        queryString,
        rowHTML,
        historyHTML,
        runAssetsHTML,
        parseListResponse,
        parseRunsResponse,
        words,
        rerenderLanguage,
        constants: {
            API_ROOT,
            PAGE_SIZE,
            POLL_IDLE_MS,
            POLL_RUNNING_MS,
            RUN_HISTORY_LIMIT,
            MIN_INTERVAL_MINUTES,
            MAX_INTERVAL_MINUTES,
            DEFAULT_INTERVAL_MINUTES,
            MAX_RESULTS,
            DEFAULT_MAX_RESULTS,
        },
    };
})();

function initAssetMonitor() { AssetMonitorPage.init(); }
function stopAssetMonitorPage() { AssetMonitorPage.stop(); }
function refreshAssetMonitors() { return AssetMonitorPage.refresh(); }
function openAssetMonitorEditor(id, button) { return AssetMonitorPage.openEditor(id, button); }
function saveAssetMonitor() { return AssetMonitorPage.save(); }
function toggleAssetMonitorEnabled(id, enabled, input) { return AssetMonitorPage.toggleEnabled(id, enabled, input); }
function runAssetMonitorNow(id, button) { return AssetMonitorPage.runNow(id, button); }
function deleteAssetMonitor(id, button) { return AssetMonitorPage.remove(id, button); }

if (typeof window !== 'undefined') {
    window.initAssetMonitor = initAssetMonitor;
    window.stopAssetMonitorPage = stopAssetMonitorPage;
    window.refreshAssetMonitors = refreshAssetMonitors;
    window.openAssetMonitorEditor = openAssetMonitorEditor;
    window.saveAssetMonitor = saveAssetMonitor;
    window.toggleAssetMonitorEnabled = toggleAssetMonitorEnabled;
    window.runAssetMonitorNow = runAssetMonitorNow;
    window.deleteAssetMonitor = deleteAssetMonitor;
}
if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    document.addEventListener('languagechange', () => AssetMonitorPage.rerenderLanguage());
}
if (typeof module !== 'undefined' && module.exports) module.exports = AssetMonitorPage;
