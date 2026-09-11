const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const rules = require('./github-leak-rules.js');

test('canonical AND rules trim, de-duplicate, sort and escape literal terms', () => {
    assert.deepEqual(rules.buildANDRule('vendor.example\nClientID\nclientid'), {
        keywords: ['clientid', 'vendor.example'],
        query: '"clientid" AND "vendor.example" in:file',
        error: '',
    });
    assert.equal(
        rules.buildANDRule('path\\key\nfoo"bar').query,
        '"foo\\"bar" AND "path\\\\key" in:file',
    );
    assert.deepEqual(rules.buildANDRule('学城'), {
        keywords: ['学城'],
        query: '"学城" in:file',
        error: '',
    });
    assert.equal(rules.buildANDRule('乐享').query, '"乐享" in:file');
});

test('rule limits match the backend boundaries', () => {
    assert.equal(rules.constants.MAX_RULES, 40);
    assert.equal(rules.constants.MAX_TERMS, 6);
    assert.match(rules.normalizeName('美'.repeat(34)).error, /100 字节/);
    assert.match(rules.normalizeName('bad\u2028name').error, /单行文本/);
    assert.match(rules.buildANDRule('a\nb').error, /2 到 200 字节/);
    assert.match(rules.buildANDRule(['aa', 'bb', 'cc', 'dd', 'ee', 'ff', 'gg']).error, /最多允许 6/);
    assert.match(rules.buildANDRule(['a'.repeat(200), 'b'.repeat(60)]).error, /256 字节/);

    const tooMany = Array.from({ length: rules.constants.MAX_RULES + 1 }, (_, index) => ({
        name: `rule-${index}`,
        enabled: true,
        keywords: [`term-${index}`],
    }));
    const validation = rules.validateRules(tooMany);
    assert.equal(validation.valid, false);
    assert.match(validation.globalErrors.join(''), /40/);
});

test('validation rejects empty rows, duplicate names and duplicate canonical queries', () => {
    const validation = rules.validateRules([
        { name: 'Example-corp', enabled: true, keywords: ['vendor.example', 'clientid'] },
        { name: 'example-corp', enabled: false, keywords: ['clientid', 'vendor.example'] },
        { name: 'empty', enabled: false, keywords: [] },
    ]);
    assert.equal(validation.valid, false);
    assert.match(validation.errors[0].name, /不能重复/);
    assert.match(validation.errors[1].name, /不能重复/);
    assert.match(validation.errors[0].keywords, /canonical 查询/);
    assert.match(validation.errors[1].keywords, /canonical 查询/);
    assert.match(validation.errors[2].keywords, /至少需要 1/);

    const caseOnlyDifference = rules.validateRules([
        { name: 'upper', enabled: true, keywords: ['VENDOR.EXAMPLE', 'CLIENTID'] },
        { name: 'lower', enabled: true, keywords: ['vendor.example', 'clientid'] },
    ]);
    assert.equal(caseOnlyDifference.valid, false);
    assert.match(caseOnlyDifference.errors[0].keywords, /canonical 查询/);
    assert.match(caseOnlyDifference.errors[1].keywords, /canonical 查询/);
});

test('master enable requires at least one enabled rule but disabled monitoring may keep none', () => {
    assert.match(rules.activationError(true, []), /至少需要一条已启用规则/);
    assert.match(rules.activationError(true, [{ name: 'paused', enabled: false, keywords: ['aa'] }]), /至少需要一条已启用规则/);
    assert.equal(rules.activationError(false, []), '');
    assert.equal(rules.activationError(true, [{ name: 'active', enabled: true, keywords: ['aa'] }]), '');
});

test('legacy keywords are migrated only when named rules are absent', () => {
    const configured = rules.rulesFromConfig({
        keywords: ['legacy.example', 'ACCESSKEY'],
        rules: [{ name: 'legacy', enabled: false, keywords: ['vendor.example', 'clientid'] }],
    });
    assert.deepEqual(configured, [
        { name: 'legacy', enabled: false, keywords: ['vendor.example', 'clientid'] },
    ]);
    assert.deepEqual(rules.rulesFromConfig({ keywords: ['legacy.example', 'ACCESSKEY'] }), [
        { name: 'legacy', enabled: true, keywords: ['legacy.example', 'ACCESSKEY'] },
    ]);
});

test('settings editor never builds rule cards with innerHTML', () => {
    const source = fs.readFileSync(require.resolve('./github-leak-rules.js'), 'utf8');
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(source, /\.textContent\s*=/);
    assert.match(source, /replaceChildren\(/);
});

test('settings page loads the rule editor before settings and saves new rules with legacy cleared', () => {
    const template = fs.readFileSync(require.resolve('../../templates/index.html'), 'utf8');
    const settings = fs.readFileSync(require.resolve('./settings.js'), 'utf8');
    const rulesScript = template.indexOf('/static/js/github-leak-rules.js');
    const settingsScript = template.indexOf('/static/js/settings.js');
    assert.ok(rulesScript >= 0 && settingsScript > rulesScript);
    assert.match(template, /id="github-leak-rules"/);
    assert.doesNotMatch(template, /id="github-leak-keywords"/);
    assert.match(settings, /rules:\s*githubLeakRules/);
    assert.match(settings, /keywords:\s*\[\]/);
    assert.match(settings, /github-leak-rules-error/);
    assert.match(settings, /activationError\(githubLeakEnabled, githubLeakRules\)/);
    assert.match(template, /id="github-leak-interval" min="31" max="86400"/);
});

test('settings page loads, validates and saves the GitHub leak lookback window', () => {
    const template = fs.readFileSync(require.resolve('../../templates/index.html'), 'utf8');
    const settings = fs.readFileSync(require.resolve('./settings.js'), 'utf8');
    assert.match(template, /id="github-leak-lookback-days" min="1" max="3650" value="365"/);
    assert.match(settings, /githubLeakLookbackDays\.value = String\(githubLeak\.lookback_days \|\| 365\)/);
    assert.match(settings, /const githubLeakLookbackDays = Number\(githubLeakLookbackDaysEl\?\.value \|\| '365'\)/);
    assert.match(settings, /githubLeakLookbackDays < 1 \|\| githubLeakLookbackDays > 3650/);
    assert.match(settings, /lookback_days:\s*githubLeakLookbackDays/);
});

// Minimal DOM fixture for editor behavior; real layout is verified in the browser.
function editorFixture() {
    const doc = { activeElement: null };
    class Node {
        constructor(tag) {
            this.tagName = tag; this.ownerDocument = doc; this.children = [];
            this.dataset = {}; this.attributes = {}; this.listeners = {};
            this.className = ''; this.hidden = false; this.value = ''; this.checked = false;
            this.classList = {
                toggle: (name, enabled) => {
                    const classes = new Set(this.className.split(' ').filter(Boolean));
                    enabled ? classes.add(name) : classes.delete(name);
                    this.className = [...classes].join(' ');
                },
                add: name => this.classList.toggle(name, true),
                remove: name => this.classList.toggle(name, false),
            };
        }
        append(...nodes) { nodes.forEach(node => this.appendChild(node)); }
        appendChild(node) {
            if (node.tagName === 'fragment') { [...node.children].forEach(child => this.appendChild(child)); return; }
            if (node.parentNode) node.parentNode.children = node.parentNode.children.filter(child => child !== node);
            node.parentNode = this; this.children.push(node);
        }
        replaceChildren(...nodes) { this.children.forEach(n => { n.parentNode = null; }); this.children = []; this.append(...nodes); }
        setAttribute(name, value) { this.attributes[name] = value; }
        addEventListener(name, listener) { (this.listeners[name] ||= []).push(listener); }
        fire(name, target = this, extra = {}) { (this.listeners[name] || []).forEach(fn => fn({target, preventDefault() {}, ...extra})); }
        focus() { doc.activeElement = this; }
        matches(selector) {
            return selector.split(',').some(part => {
                part = part.trim();
                const data = part.match(/^\[data-([^=\]]+)(?:="([^"]+)")?\]$/);
                if (data) {
                    const key = data[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase());
                    return data[2] === undefined ? key in this.dataset : this.dataset[key] === data[2];
                }
                const [tag, cls] = part.split('.');
                return (!tag || this.tagName === tag) && (!cls || this.className.split(' ').includes(cls));
            });
        }
        querySelectorAll(selector) { return this.children.flatMap(n => [...(n.matches(selector) ? [n] : []), ...n.querySelectorAll(selector)]); }
        querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
        closest(selector) { return this.matches(selector) ? this : this.parentNode?.closest(selector); }
    }
    doc.createElement = tag => new Node(tag);
    doc.createDocumentFragment = () => new Node('fragment');
    const container = new Node('div'); container.id = 'test-rules';
    const addButton = new Node('button'); const toggleMount = new Node('div');
    const errorOutput = new Node('output');
    const editor = rules.createEditor({container, addButton, toggleMount, errorOutput});
    return {doc, container, addButton, toggle: toggleMount.querySelector('button'), count: toggleMount.querySelector('.ghl-settings-rules-count'), editor};
}

test('rule disclosure starts collapsed, preserves hidden form values and updates enabled counts', () => {
    const f = editorFixture();
    f.editor.load({rules: [{name: 'sample', enabled: true, keywords: ['example.com']}]});
    assert.equal(f.container.hidden, true);
    assert.equal(f.toggle.attributes['aria-expanded'], 'false');
    assert.equal(f.toggle.attributes['aria-controls'], 'test-rules');
    assert.equal(f.count.textContent, '1 条 · 1 条启用');
    f.toggle.fire('click');
    f.container.querySelector('[data-ghl-rule-name]').value = 'edited';
    const enabled = f.container.querySelector('[data-ghl-rule-enabled]'); enabled.checked = false;
    f.container.fire('change', enabled);
    f.toggle.fire('click');
    assert.equal(f.container.hidden, true);
    assert.deepEqual(f.editor.read().rules, [{name: 'edited', enabled: false, keywords: ['example.com']}]);
    assert.equal(f.container.hidden, true, 'valid hidden rules need not be expanded during save');
    assert.equal(f.count.textContent, '1 条 · 0 条启用');
});

test('adding and invalid save reveal rules, Escape closes without losing input', () => {
    const f = editorFixture();
    f.addButton.fire('click');
    assert.equal(f.container.hidden, false);
    assert.equal(f.doc.activeElement, f.container.querySelector('[data-ghl-rule-name]'));
    f.container.fire('keydown', f.doc.activeElement, {key: 'Escape'});
    assert.equal(f.container.querySelector('[data-ghl-rule-card]').open, false);
    assert.equal(f.doc.activeElement, f.container.querySelector('summary'));
    f.container.fire('keydown', f.doc.activeElement, {key: 'Escape'});
    assert.equal(f.container.hidden, true);
    assert.equal(f.doc.activeElement, f.toggle);
    assert.equal(f.editor.read().valid, false);
    assert.equal(f.container.hidden, false);
    assert.equal(f.container.querySelector('[data-ghl-rule-card]').open, true);
    assert.equal(f.doc.activeElement, f.container.querySelector('[data-ghl-rule-name]'));
    f.container.fire('click', f.container.querySelector('[data-ghl-rule-remove]'));
    assert.equal(f.editor.count(), 0);
    assert.equal(f.count.textContent, '0 条 · 0 条启用');
});

test('individual rules are folded with useful summaries and keep edits through add/remove', () => {
    const f = editorFixture();
    f.editor.load({rules: [
        {name: 'first', enabled: true, keywords: ['example.com', 'clientid']},
        {name: 'second', enabled: false, keywords: ['other.example']},
    ]});
    const cards = () => f.container.querySelectorAll('[data-ghl-rule-card]');
    assert.ok(cards().every(card => card.tagName === 'details' && !card.open));
    assert.equal(cards()[0].querySelector('.ghl-settings-rule-number').textContent, '规则 1 · first');
    assert.equal(cards()[1].querySelector('.ghl-settings-rule-summary-state').textContent, '已停用 · 1 个词');
    cards()[0].open = true;
    const input = cards()[0].querySelector('[data-ghl-rule-name]');
    input.value = 'edited'; f.container.fire('input', input);
    assert.equal(cards()[0].querySelector('.ghl-settings-rule-number').textContent, '规则 1 · edited');
    f.editor.add({name:'third', enabled:true, keywords:['third.example']});
    assert.deepEqual(cards().map(card => card.open), [true, false, true]);
    f.container.fire('click', cards()[1].querySelector('[data-ghl-rule-remove]'));
    assert.deepEqual(cards().map(card => card.open), [true, true]);
    assert.deepEqual(f.editor.read().rules.map(rule => rule.name), ['edited', 'third']);
});
