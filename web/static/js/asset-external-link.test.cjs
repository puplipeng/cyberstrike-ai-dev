const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const source = fs.readFileSync('web/static/js/assets.js', 'utf8');
const html = fs.readFileSync('web/templates/index.html', 'utf8');
const css = fs.readFileSync('web/static/css/style.css', 'utf8');
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

function functionSource(name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end).trim();
}

const externalURL = vm.runInNewContext(`(${functionSource('assetExternalURL', 'assetExternalLinkMarkup')})`, { URL });

test('assetExternalURL preserves safe absolute HTTP URLs', () => {
    assert.equal(
        externalURL({ host: 'https://Example.COM/a/b?x=1#result', protocol: 'ssh', port: 22 }),
        'https://example.com/a/b?x=1#result'
    );
    assert.equal(externalURL({ host: 'http://example.com:8080/login' }), 'http://example.com:8080/login');
});

test('assetExternalURL builds web URLs from protocol, host, IP, and port', () => {
    assert.equal(externalURL({ domain: 'example.com', protocol: 'http', port: 8080 }), 'http://example.com:8080/');
    assert.equal(externalURL({ ip: '2001:db8::1', protocol: 'https', port: 8443 }), 'https://[2001:db8::1]:8443/');
    assert.equal(externalURL({ domain: 'example.com', port: 80 }), 'http://example.com/');
    assert.equal(externalURL({ host: 'example.com:443' }), 'https://example.com/');
    assert.equal(externalURL({ domain: 'example.com', protocol: 'https', port: 443 }), 'https://example.com/');
});

test('assetExternalURL does not guess links for non-web services or unknown ports', () => {
    for (const asset of [
        { domain: 'example.com', protocol: 'ssh', port: 22 },
        { domain: 'example.com', protocol: 'ftp', port: 21 },
        { domain: 'example.com', protocol: 'tcp', port: 443 },
        { domain: 'example.com', port: 22 },
        { domain: 'example.com' }
    ]) assert.equal(externalURL(asset), '');
});

test('assetExternalURL rejects dangerous or malformed targets', () => {
    for (const asset of [
        { host: 'javascript:alert(1)' },
        { host: 'data:text/html,boom' },
        { host: 'https://user:secret@example.com/' },
        { host: 'https://example.com\\@evil.example/' },
        { host: 'https://example.com/ bad' },
        { host: 'https://example.com/\nnext' },
        { host: ' javascript:alert(1)', domain: 'example.com', protocol: 'https', port: 443 },
        { host: 'javascript:alert(1)', domain: 'example.com', protocol: 'https', port: 443 },
        { host: 'example.com:80', protocol: 'https', port: 443 },
        { domain: 'example.com/path', protocol: 'https', port: 443 },
        { domain: 'example.com', protocol: 'https', port: 70000 },
        { domain: 'example.com', protocol: 'https', port: '443x' },
        { host: 'https://' }
    ]) assert.equal(externalURL(asset), '');
});

test('asset external link markup escapes text and has safe new-tab attributes', () => {
    const targetLabel = vm.runInNewContext(`(${functionSource('assetTargetLabel', 'assetExternalURL')})`);
    const escape = value => String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const markupFn = vm.runInNewContext(`(${functionSource('assetExternalLinkMarkup', 'assetRiskPresentation')})`, {
        assetExternalURL: externalURL,
        assetTargetLabel: targetLabel,
        assetT: () => '"><img src=x onerror=alert(1)>',
        assetEscapeAttr: escape,
        escapeHtml: escape
    });
    const markup = markupFn({ host: 'https://example.com/a?x=%22' }, 'detail');
    assert.match(markup, /target="_blank"/);
    assert.match(markup, /rel="noopener noreferrer"/);
    assert.match(markup, /referrerpolicy="no-referrer"/);
    assert.match(markup, /href="https:\/\/example\.com\/a\?x=%22"/);
    assert.doesNotMatch(markup, /<img/);
    assert.equal(markupFn({ domain: 'example.com', protocol: 'ssh', port: 22 }), '');
});

test('asset list and detail keep their existing behavior and add one-click external links', () => {
    const rows = functionSource('renderAssetRows', 'toggleAssetSelection');
    const detail = functionSource('assetDetailOverview', 'openAssetDetail');
    assert.match(rows, /openAssetDetail\(\$\{index\}\)/);
    assert.match(rows, /assetExternalLinkMarkup\(asset\)/);
    assert.match(detail, /assetExternalLinkMarkup\(asset, 'detail'\)/);
    assert.match(css, /\.asset-target-cell/);
    assert.match(css, /\.asset-external-link--detail/);
    assert.match(css, /\.asset-target-cell \.asset-external-link \{[\s\S]*?width: 40px;[\s\S]*?height: 40px;/);
});

test('asset external-link translations and cache busting are wired', () => {
    assert.equal(zh.assets.openExternal, '打开外链');
    assert.equal(en.assets.openExternal, 'Open link');
    assert.match(html, /\/static\/js\/assets\.js\?v=20260904-src6kskill1/);
    assert.match(html, /\/static\/css\/style\.css\?v=20260904-src6kskill1/);
});
