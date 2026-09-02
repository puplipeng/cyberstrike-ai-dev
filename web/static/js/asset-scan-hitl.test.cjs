const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const assets = fs.readFileSync('web/static/js/assets.js', 'utf8');
const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const html = fs.readFileSync('web/templates/index.html', 'utf8');
const css = fs.readFileSync('web/static/css/style.css', 'utf8');

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end).trim();
}

test('资产扫描弹窗在提示词和任务启动前确认审批策略', () => {
    const approvalIndex = html.indexOf('id="asset-scan-hitl-mode"');
    const promptIndex = html.indexOf('id="asset-scan-prompt"');
    const submitIndex = html.indexOf('id="asset-scan-submit"');

    assert.notEqual(approvalIndex, -1);
    assert.ok(approvalIndex < promptIndex);
    assert.ok(promptIndex < submitIndex);
    assert.match(html, /id="asset-scan-hitl-mode"[\s\S]*?<option value="off"/);
    assert.match(html, /id="asset-scan-hitl-reviewer"/);
    assert.match(html, /id="asset-scan-hitl-timeout"/);
    assert.match(css, /\.asset-scan-approval-grid/);
});

test('资产扫描首次使用默认关闭审批并规范化审批参数', () => {
    const source = functionSource(assets, 'normalizeAssetScanHITLConfig', 'storedAssetScanHITLConfig');
    const normalize = vm.runInNewContext(`(${source})`);

    assert.deepEqual(
        JSON.parse(JSON.stringify(normalize(null))),
        { enabled: false, mode: 'off', reviewer: 'human', sensitiveTools: [], timeoutSeconds: 300 }
    );
    assert.deepEqual(
        JSON.parse(JSON.stringify(normalize({ mode: 'review_edit', reviewer: 'audit_agent', timeoutSeconds: 0 }))),
        { enabled: true, mode: 'review_edit', reviewer: 'audit_agent', sensitiveTools: [], timeoutSeconds: 0 }
    );
});

test('单次扫描先持久化审批配置再发送，批量扫描随队列保存配置', () => {
    const sendSource = functionSource(assets, 'sendAssetsToChat', 'createAssetScanTasks');
    const batchSource = functionSource(assets, 'createAssetScanTasks', 'openAssetVulnerabilities');
    const chatSendStart = chat.indexOf('async function sendMessage()');
    const chatSendEnd = chat.indexOf('function renderChatFileChips', chatSendStart);
    const chatSendSource = chat.slice(chatSendStart, chatSendEnd);

    assert.ok(sendSource.indexOf('persistAssetScanConversationHITL') < sendSource.indexOf('void sendMessage()'));
    assert.match(sendSource, /window\.__csNextChatHITLConfig = confirmedHITL/);
    assert.match(batchSource, /hitl: normalizeAssetScanHITLConfig\(hitlConfig\)/);
    assert.match(chatSendSource, /confirmedAssetScanHITL/);
    assert.match(chatSendSource, /enabled: hitlMode !== HITL_MODE_OFF/);
    assert.match(html, /assets\.js\?v=20260830-prehitl1/);
    assert.match(html, /chat\.js\?v=20260830-pageview1/);
    assert.match(html, /style\.css\?v=20260830-prehitl1/);
});
