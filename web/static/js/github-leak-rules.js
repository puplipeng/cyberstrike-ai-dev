/* GitHub leak rule normalization and DOM-safe settings editor. */
const GitHubLeakRules = (() => {
    const MAX_RULES = 32;
    const MAX_TERMS = 6;
    const MAX_NAME_BYTES = 100;
    const MAX_TERM_BYTES = 200;
    const MAX_LITERAL_BYTES = 256;

    function utf8ByteLength(value) {
        const text = String(value == null ? '' : value);
        let bytes = 0;
        for (let index = 0; index < text.length; index++) {
            const code = text.charCodeAt(index);
            if (code <= 0x7f) {
                bytes += 1;
            } else if (code <= 0x7ff) {
                bytes += 2;
            } else if (code >= 0xd800 && code <= 0xdbff) {
                const low = text.charCodeAt(index + 1);
                if (low < 0xdc00 || low > 0xdfff) return Number.POSITIVE_INFINITY;
                bytes += 4;
                index++;
            } else if (code >= 0xdc00 && code <= 0xdfff) {
                return Number.POSITIVE_INFINITY;
            } else {
                bytes += 3;
            }
        }
        return bytes;
    }

    function hasInvalidSingleLineCharacter(value) {
        return /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(String(value));
    }

    function rawKeywords(value) {
        const values = Array.isArray(value) ? value : String(value == null ? '' : value).split(/\r?\n/);
        return values.map(item => String(item == null ? '' : item).trim()).filter(Boolean);
    }

    function buildANDRule(value) {
        const values = rawKeywords(value);
        if (values.length > MAX_TERMS) {
            return { keywords: [], query: '', error: `每条规则最多允许 ${MAX_TERMS} 个同时命中词` };
        }
        const byFoldedValue = new Map();
        for (const keyword of values) {
            const bytes = utf8ByteLength(keyword);
            if (bytes < 2 || bytes > MAX_TERM_BYTES || hasInvalidSingleLineCharacter(keyword)) {
                return { keywords: [], query: '', error: `每个同时命中词必须是 2 到 ${MAX_TERM_BYTES} 字节的单行文本` };
            }
            const folded = keyword.toLowerCase();
            const current = byFoldedValue.get(folded);
            if (current === undefined || keyword === folded || (current !== folded && keyword < current)) {
                byFoldedValue.set(folded, keyword);
            }
        }
        const keywords = Array.from(byFoldedValue.values()).sort((left, right) => {
            const foldedLeft = left.toLowerCase();
            const foldedRight = right.toLowerCase();
            if (foldedLeft === foldedRight) return left < right ? -1 : (left > right ? 1 : 0);
            return foldedLeft < foldedRight ? -1 : 1;
        });
        let literalBytes = 0;
        const terms = keywords.map(keyword => {
            const escaped = keyword.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            literalBytes += utf8ByteLength(escaped) + 2;
            return `"${escaped}"`;
        });
        if (literalBytes > MAX_LITERAL_BYTES) {
            return { keywords: [], query: '', error: `每条规则的查询字面量合计不能超过 ${MAX_LITERAL_BYTES} 字节` };
        }
        return { keywords, query: terms.length ? `${terms.join(' AND ')} in:file` : '', error: '' };
    }

    function normalizeName(value) {
        const name = String(value == null ? '' : value).trim();
        const bytes = utf8ByteLength(name);
        if (bytes < 1 || bytes > MAX_NAME_BYTES || hasInvalidSingleLineCharacter(name)) {
            return { name: '', error: `规则名称必须是 1 到 ${MAX_NAME_BYTES} 字节的单行文本` };
        }
        return { name, error: '' };
    }

    function validateRules(input) {
        const rows = Array.isArray(input) ? input : [];
        const errors = rows.map(() => ({ name: '', keywords: '' }));
        const globalErrors = [];
        if (rows.length > MAX_RULES) globalErrors.push(`最多只能配置 ${MAX_RULES} 条规则`);
        const rules = [];
        const nameIndexes = new Map();
        const queryIndexes = new Map();

        rows.slice(0, MAX_RULES).forEach((row, index) => {
            const value = row && typeof row === 'object' ? row : {};
            const normalizedName = normalizeName(value.name);
            const normalizedRule = buildANDRule(value.keywords);
            if (normalizedName.error) errors[index].name = normalizedName.error;
            if (normalizedRule.error) errors[index].keywords = normalizedRule.error;
            if (!normalizedRule.error && normalizedRule.keywords.length === 0) {
                errors[index].keywords = '每条规则至少需要 1 个同时命中词';
            }

            if (!normalizedName.error) {
                const foldedName = normalizedName.name.toLowerCase();
                if (nameIndexes.has(foldedName)) {
                    const first = nameIndexes.get(foldedName);
                    errors[first].name = errors[first].name || '规则名称不能重复（不区分大小写）';
                    errors[index].name = '规则名称不能重复（不区分大小写）';
                } else {
                    nameIndexes.set(foldedName, index);
                }
            }
            if (!normalizedRule.error && normalizedRule.query) {
                const queryKey = normalizedRule.query.toLowerCase();
                if (queryIndexes.has(queryKey)) {
                    const first = queryIndexes.get(queryKey);
                    errors[first].keywords = errors[first].keywords || '不同规则不能生成相同的 canonical 查询';
                    errors[index].keywords = '不同规则不能生成相同的 canonical 查询';
                } else {
                    queryIndexes.set(queryKey, index);
                }
            }
            rules.push({
                name: normalizedName.name,
                enabled: value.enabled === true,
                keywords: normalizedRule.keywords,
            });
        });

        const valid = globalErrors.length === 0 && errors.every(error => !error.name && !error.keywords);
        return { valid, rules, errors, globalErrors };
    }

    function activationError(enabled, rules) {
        if (enabled === true && !(Array.isArray(rules) && rules.some(rule => rule && rule.enabled === true))) {
            return '启用后台监控时至少需要一条已启用规则';
        }
        return '';
    }

    function rulesFromConfig(config) {
        const value = config && typeof config === 'object' ? config : {};
        const rules = Array.isArray(value.rules) ? value.rules.slice(0, MAX_RULES).map(rule => ({
            name: String(rule && rule.name || ''),
            enabled: !!(rule && rule.enabled),
            keywords: Array.isArray(rule && rule.keywords) ? rule.keywords.map(String) : [],
        })) : [];
        const legacyKeywords = Array.isArray(value.keywords) ? value.keywords.map(String).filter(keyword => keyword.trim()) : [];
        if (!rules.length && legacyKeywords.length) {
            rules.push({ name: 'legacy', enabled: true, keywords: legacyKeywords });
        }
        return rules;
    }

    function createEditor(options) {
        const container = options && options.container;
        const addButton = options && options.addButton;
        const errorOutput = options && options.errorOutput;
        if (!container || !addButton) return null;
        const doc = container.ownerDocument || document;

        function make(tag, className, text) {
            const node = doc.createElement(tag);
            if (className) node.className = className;
            if (text !== undefined) node.textContent = text;
            return node;
        }

        function fieldError(card, field) {
            return card.querySelector(`[data-ghl-rule-error="${field}"]`);
        }

        function updatePreview(card) {
            const textarea = card.querySelector('[data-ghl-rule-keywords]');
            const preview = card.querySelector('[data-ghl-rule-preview]');
            const rule = buildANDRule(textarea ? textarea.value : '');
            if (preview) {
                preview.textContent = rule.error ? `规则错误：${rule.error}` : `实际查询：${rule.query || '—'}`;
                preview.classList.toggle('error', !!rule.error);
            }
            return rule;
        }

        function createCard(rule, index) {
            const value = rule && typeof rule === 'object' ? rule : {};
            const card = make('article', 'ghl-settings-rule-card');
            card.dataset.ghlRuleCard = '1';

            const header = make('div', 'ghl-settings-rule-card-header');
            const title = make('strong', 'ghl-settings-rule-number', `规则 ${index + 1}`);
            const actions = make('div', 'ghl-settings-rule-card-actions');
            const enabledLabel = make('label', 'ghl-settings-rule-enabled');
            const enabled = doc.createElement('input');
            enabled.type = 'checkbox';
            enabled.checked = value.enabled === true;
            enabled.dataset.ghlRuleEnabled = '1';
            enabledLabel.append(enabled, make('span', '', '启用'));
            const remove = make('button', 'btn-secondary btn-small', '删除');
            remove.type = 'button';
            remove.dataset.ghlRuleRemove = '1';
            actions.append(enabledLabel, remove);
            header.append(title, actions);

            const nameGroup = make('div', 'form-group ghl-settings-rule-name');
            const nameLabel = make('label', '', '规则名称');
            const name = doc.createElement('input');
            name.id = `github-leak-rule-name-${index}`;
            nameLabel.htmlFor = name.id;
            name.type = 'text';
            name.maxLength = MAX_NAME_BYTES;
            name.autocomplete = 'off';
            name.placeholder = '例如：example-corp-clientid';
            name.value = String(value.name || '');
            name.dataset.ghlRuleName = '1';
            const nameError = make('small', 'form-hint ghl-settings-rule-error');
            nameError.dataset.ghlRuleError = 'name';
            nameGroup.append(nameLabel, name, nameError);

            const keywordsGroup = make('div', 'form-group ghl-settings-rule-keywords');
            const keywordsLabel = make('label', '', `同时命中词（每行一个，最多 ${MAX_TERMS} 个）`);
            const keywords = doc.createElement('textarea');
            keywords.id = `github-leak-rule-keywords-${index}`;
            keywordsLabel.htmlFor = keywords.id;
            keywords.rows = 4;
            keywords.spellcheck = false;
            keywords.placeholder = 'vendor.example\nclientid';
            keywords.value = Array.isArray(value.keywords) ? value.keywords.join('\n') : String(value.keywords || '');
            keywords.dataset.ghlRuleKeywords = '1';
            const hint = make('small', 'form-hint', '每行按精确字面量处理；平台会排序、去重并生成 AND 查询。');
            const preview = make('output', 'form-hint ghl-settings-query-preview', '实际查询：—');
            preview.dataset.ghlRulePreview = '1';
            preview.setAttribute('aria-live', 'polite');
            const keywordsError = make('small', 'form-hint ghl-settings-rule-error');
            keywordsError.dataset.ghlRuleError = 'keywords';
            keywordsGroup.append(keywordsLabel, keywords, hint, preview, keywordsError);

            card.append(header, nameGroup, keywordsGroup);
            updatePreview(card);
            return card;
        }

        function cards() {
            return Array.from(container.querySelectorAll('[data-ghl-rule-card]'));
        }

        function readRaw() {
            return cards().map(card => ({
                name: card.querySelector('[data-ghl-rule-name]')?.value || '',
                enabled: card.querySelector('[data-ghl-rule-enabled]')?.checked === true,
                keywords: card.querySelector('[data-ghl-rule-keywords]')?.value || '',
            }));
        }

        function updateEmptyState() {
            const empty = container.querySelector('[data-ghl-rules-empty]');
            if (empty) empty.hidden = cards().length > 0;
            addButton.disabled = cards().length >= MAX_RULES;
        }

        function render(rows) {
            const safeRows = Array.isArray(rows) ? rows.slice(0, MAX_RULES) : [];
            const fragment = doc.createDocumentFragment();
            const empty = make('p', 'form-hint ghl-settings-rules-empty', '尚未配置规则。点击“新增规则”开始配置。');
            empty.dataset.ghlRulesEmpty = '1';
            fragment.appendChild(empty);
            safeRows.forEach((row, index) => fragment.appendChild(createCard(row, index)));
            container.replaceChildren(fragment);
            if (errorOutput) errorOutput.textContent = '';
            updateEmptyState();
        }

        function showValidation() {
            const result = validateRules(readRaw());
            cards().forEach((card, index) => {
                const rowError = result.errors[index] || { name: '', keywords: '' };
                const name = card.querySelector('[data-ghl-rule-name]');
                const keywords = card.querySelector('[data-ghl-rule-keywords]');
                if (name) name.classList.toggle('error', !!rowError.name);
                if (keywords) keywords.classList.toggle('error', !!rowError.keywords);
                const nameError = fieldError(card, 'name');
                const keywordsError = fieldError(card, 'keywords');
                if (nameError) nameError.textContent = rowError.name;
                if (keywordsError) keywordsError.textContent = rowError.keywords;
                updatePreview(card);
            });
            if (errorOutput) errorOutput.textContent = result.globalErrors.join('；');
            return result;
        }

        function add(rule) {
            const rows = readRaw();
            if (rows.length >= MAX_RULES) {
                if (errorOutput) errorOutput.textContent = `最多只能配置 ${MAX_RULES} 条规则`;
                return false;
            }
            rows.push(rule && typeof rule === 'object' ? rule : { name: '', enabled: true, keywords: [] });
            render(rows);
            const list = cards();
            const input = list[list.length - 1]?.querySelector('[data-ghl-rule-name]');
            if (input && typeof input.focus === 'function') input.focus();
            return true;
        }

        addButton.addEventListener('click', () => add());
        container.addEventListener('click', event => {
            const button = event.target.closest && event.target.closest('[data-ghl-rule-remove]');
            if (!button) return;
            const card = button.closest('[data-ghl-rule-card]');
            const rows = readRaw();
            const index = cards().indexOf(card);
            if (index >= 0) rows.splice(index, 1);
            render(rows);
        });
        container.addEventListener('input', event => {
            const card = event.target.closest && event.target.closest('[data-ghl-rule-card]');
            if (!card) return;
            event.target.classList.remove('error');
            if (event.target.matches('[data-ghl-rule-keywords]')) updatePreview(card);
            const field = event.target.matches('[data-ghl-rule-name]') ? 'name' : 'keywords';
            const output = fieldError(card, field);
            if (output) output.textContent = '';
            if (errorOutput) errorOutput.textContent = '';
        });

        render([]);
        return {
            load(config) { render(rulesFromConfig(config)); },
            read: showValidation,
            add,
            count() { return cards().length; },
        };
    }

    return {
        buildANDRule,
        normalizeName,
        validateRules,
        activationError,
        rulesFromConfig,
        createEditor,
        constants: { MAX_RULES, MAX_TERMS, MAX_NAME_BYTES, MAX_TERM_BYTES, MAX_LITERAL_BYTES },
    };
})();

if (typeof window !== 'undefined') window.GitHubLeakRules = GitHubLeakRules;
if (typeof module !== 'undefined' && module.exports) module.exports = GitHubLeakRules;
