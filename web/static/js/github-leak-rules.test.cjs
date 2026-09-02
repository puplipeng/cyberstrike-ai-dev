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
});

test('rule limits match the backend boundaries', () => {
    assert.equal(rules.constants.MAX_RULES, 32);
    assert.equal(rules.constants.MAX_TERMS, 6);
    assert.match(rules.normalizeName('美'.repeat(34)).error, /100 字节/);
    assert.match(rules.normalizeName('bad\u2028name').error, /单行文本/);
    assert.match(rules.buildANDRule('a\nb').error, /2 到 200 字节/);
    assert.match(rules.buildANDRule(['aa', 'bb', 'cc', 'dd', 'ee', 'ff', 'gg']).error, /最多允许 6/);
    assert.match(rules.buildANDRule(['a'.repeat(200), 'b'.repeat(60)]).error, /256 字节/);

    const tooMany = Array.from({ length: 33 }, (_, index) => ({
        name: `rule-${index}`,
        enabled: true,
        keywords: [`term-${index}`],
    }));
    const validation = rules.validateRules(tooMany);
    assert.equal(validation.valid, false);
    assert.match(validation.globalErrors.join(''), /32/);
});

test('validation rejects empty rows, duplicate names and duplicate canonical queries', () => {
    const validation = rules.validateRules([
        { name: 'example-corp', enabled: true, keywords: ['vendor.example', 'clientid'] },
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
        { name: 'upper', enabled: true, keywords: ['vendor.example', 'CLIENTID'] },
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
