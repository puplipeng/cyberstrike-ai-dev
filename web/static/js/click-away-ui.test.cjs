const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

function read(name) {
    return fs.readFileSync(`web/static/js/${name}`, 'utf8');
}

const html = fs.readFileSync('web/templates/index.html', 'utf8');

test('header menus close on Escape and keep aria-expanded synchronized', () => {
    const auth = read('auth.js');
    const notifications = read('notifications.js');
    const i18n = read('i18n.js');

    assert.match(auth, /event\.key === 'Escape'[\s\S]*?setUserMenuOpen\(false\)/);
    assert.match(notifications, /event\.key === 'Escape'[\s\S]*?closeDropdown\(\)/);
    assert.match(notifications, /bellBtn\.setAttribute\('aria-expanded', 'true'\)/);
    assert.match(notifications, /bellBtn\.setAttribute\('aria-expanded', 'false'\)/);
    assert.match(i18n, /event\.key === 'Escape'[\s\S]*?closeLangDropdown\(\)/);
    assert.match(i18n, /btn\.setAttribute\('aria-expanded', willOpen \? 'true' : 'false'\)/);
    assert.match(html, /id="notification-bell-btn"[^>]*aria-expanded="false"/);
    assert.match(html, /class="btn-secondary lang-switcher-btn"[^>]*aria-expanded="false"/);
});

test('chat approval card and transient menus close away from their trigger', () => {
    const chat = read('chat.js');

    assert.match(chat, /function dismissHitlSidebarCardOnOutsideInteraction/);
    assert.match(chat, /card\.contains\(event\.target\)/);
    assert.match(chat, /addEventListener\('pointerdown', dismissHitlSidebarCardOnOutsideInteraction\)/);
    assert.match(chat, /typeof closeContextMenu === 'function'\) closeContextMenu\(\)/);
    assert.match(chat, /function dismissChatTransientLayersOnEscape[\s\S]*?closeHitlSidebarCard\(\)/);
});

test('FOFA columns and audit export close outside or on Escape', () => {
    const info = read('info-collect.js');
    const audit = read('audit.js');

    assert.match(info, /id=['"]fofa-columns-toggle|fofa-columns-toggle/);
    assert.match(info, /e\.key === 'Escape'[\s\S]*?closeFofaColumnsPanel\(\)/);
    assert.match(audit, /wrapper\.contains\(event\.target\)/);
    assert.match(audit, /event\.key === 'Escape'[\s\S]*?closeAuditExportMenu\(\)/);
    assert.match(html, /id="fofa-columns-toggle"[^>]*aria-expanded="false"/);
});

test('WebShell selectors and action menus dismiss consistently', () => {
    const webshell = read('webshell.js');

    assert.match(webshell, /wsCloseRolePanel\(\);[\s\S]*?wsCloseAgentModePanel\(\);[\s\S]*?wsCloseProjectPanel\(\);/);
    assert.match(webshell, /btn\.setAttribute\('aria-expanded', 'true'\)/);
    assert.match(webshell, /var openSelector = 'details\.webshell-conn-actions\[open\],details\.webshell-row-actions\[open\],details\.webshell-toolbar-actions\[open\]'/);
    assert.match(webshell, /summary\.closest\(selector\) === clickedInMenu/);
    assert.match(webshell, /e\.key === 'Escape'\) closeMenus\(null\)/);
    assert.doesNotMatch(webshell, /querySelectorAll\(['"]details\[open\]['"]\)/);
});

test('knowledge category and workflow action menus support Escape', () => {
    const knowledge = read('knowledge.js');
    const workflows = read('workflows.js');

    assert.match(knowledge, /e\.key === 'Escape'[\s\S]*?wrapper\.classList\.remove\('open'\)/);
    assert.match(knowledge, /trigger\.setAttribute\('aria-expanded', 'false'\)/);
    assert.match(workflows, /event\.key === 'Escape'\) window\.closeWorkflowMoreActions\(\)/);
    assert.match(html, /id="knowledge-category-filter-trigger"[^>]*aria-expanded="false"/);
});

test('changed scripts are cache-busted', () => {
    for (const name of ['i18n', 'notifications', 'info-collect', 'audit', 'knowledge', 'workflows']) {
        assert.match(html, new RegExp(`/static/js/${name}\\.js\\?v=20260830-dismiss1`));
    }
    for (const name of ['router', 'auth']) {
        assert.match(html, new RegExp(`/static/js/${name}\\.js\\?v=20260901-ghleak1`));
    }
    assert.match(html, /\/static\/js\/github-leak-rules\.js\?v=20260902-rules1/);
    assert.match(html, /\/static\/js\/settings\.js\?v=20260902-ghleak-rules1/);
    assert.match(html, /\/static\/js\/github-leaks\.js\?v=20260902-partial2/);
    assert.match(html, /\/static\/css\/github-leaks\.css\?v=20260902-rules2/);
    for (const name of ['monitor', 'webshell']) {
        assert.match(html, new RegExp(`/static/js/${name}\\.js\\?v=20260830-codexargs1`));
    }
    assert.match(html, /\/static\/js\/chat\.js\?v=20260830-pageview1/);
});
