const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = process.cwd();
const settings = fs.readFileSync(path.join(root, 'web/static/js/settings.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('Eino 模型 retry/failover 设置页读写链路完整', () => {
    [
        'eino-model-retry-max-retries',
        'eino-model-retry-max-backoff-sec',
        'eino-model-failover-channels',
        'eino-model-failover-max-retries'
    ].forEach((id) => {
        assert.match(template, new RegExp(`id="${id}"`));
        assert.match(settings, new RegExp(`getElementById\\('${id}'\\)`));
    });

    [
        'model_retry_max_retries',
        'model_retry_max_backoff_sec',
        'model_failover_channels',
        'model_failover_max_retries'
    ].forEach((key) => {
        assert.match(settings, new RegExp(`${key}`));
    });

    assert.match(settings, /failoverChannelsRaw\.split\(\s*\/\[\\n,，\]\//);
    assert.match(settings, /Array\.from\(new Set\(/);
});

test('Eino 模型 retry/failover 设置项有中英文文案', () => {
    [
        'einoModelRetryMaxRetries',
        'einoModelRetryMaxRetriesHint',
        'einoModelRetryMaxBackoffSec',
        'einoModelRetryMaxBackoffSecHint',
        'einoModelFailoverChannels',
        'einoModelFailoverChannelsPlaceholder',
        'einoModelFailoverChannelsHint',
        'einoModelFailoverMaxRetries',
        'einoModelFailoverMaxRetriesHint'
    ].forEach((key) => {
        assert.equal(typeof zh.settingsBasic[key], 'string', `zh ${key}`);
        assert.ok(zh.settingsBasic[key].length > 0, `zh ${key} is empty`);
        assert.equal(typeof en.settingsBasic[key], 'string', `en ${key}`);
        assert.ok(en.settingsBasic[key].length > 0, `en ${key} is empty`);
    });
});

test('AI 通道保存前会自动识别 DeepSeek 官方线路', () => {
    assert.match(settings, /function\s+isOfficialDeepSeekBaseURL/);
    assert.match(settings, /api\.deepseek\.com/);
    assert.match(settings, /profile:\s*'deepseek'/);
    assert.match(settings, /normalizeAIChannelProviderProfile\(\{/);
    assert.match(settings, /normalizeAIConfigProviderProfiles\(currentConfig\.ai\)/);
    assert.match(template, /<option value="deepseek">deepseek<\/option>/);
});

test('切换或新增 AI 通道时会刷新推理线路下拉显示', () => {
    assert.match(settings, /const profileEl = document\.getElementById\('openai-reasoning-profile'\);/);
    assert.match(settings, /syncSettingsCustomSelect\(profileEl\);/);
    assert.match(settings, /reasoning:\s*\{\s*mode:\s*'auto',\s*effort:\s*'',\s*profile:\s*'auto'/);
});


test('Codex 账号通道免填 URL 和密钥，其他通道仍校验', () => {
    const vm = require('node:vm');
    const source = settings.match(/function validateSelectedAIChannelPayload\(ch\) \{[\s\S]*?\n\}/)[0];
    const ctx = vm.createContext({});
    vm.runInContext(source, ctx);
    assert.equal(ctx.validateSelectedAIChannelPayload({provider:'codex_account', model:'test-model'}), '');
    assert.equal(ctx.validateSelectedAIChannelPayload({provider:'codex_account'}), '模型');
    assert.match(ctx.validateSelectedAIChannelPayload({provider:'openai', model:'test-model'}), /API Key/);
});

test('Codex 账号字段切换后恢复普通 API 字段状态', () => {
    const vm = require('node:vm');
    const elements = {
        'openai-provider': {value:'codex_account'},
        'codex-account-hint': {style:{}},
        'codex-output-budget-hint': {style:{}}
    };
    for (const id of ['openai-api-key','openai-base-url']) {
        const group = {style:{}};
        elements[id] = {required:true, disabled:false, closest:()=>group};
    }
    const ctx = vm.createContext({document:{getElementById:id=>elements[id]}});
    const source = settings.match(/function syncCodexAccountFields\(\) \{[\s\S]*?\n\}/)[0];
    vm.runInContext(source,ctx);
    ctx.syncCodexAccountFields();
    assert.equal(elements['openai-api-key'].required,false);
    assert.equal(elements['openai-api-key'].disabled,true);
    assert.equal(elements['codex-account-hint'].style.display,'');
    assert.equal(elements['codex-output-budget-hint'].style.display,'');
    elements['openai-provider'].value='openai_compatible';
    ctx.syncCodexAccountFields();
    assert.equal(elements['openai-api-key'].required,true);
    assert.equal(elements['openai-api-key'].disabled,false);
    assert.equal(elements['openai-api-key'].closest().style.display,'');
    assert.equal(elements['codex-output-budget-hint'].style.display,'none');
});

test('task budget and token optimization switches survive edit/save without treating unlimited as default', () => {
    const vm = require('node:vm');
    const elements = {
        'agent-max-task-tokens': {value:''},
        'eino-tool-search-enable': {checked:false},
        'eino-reduction-enable': {checked:false}
    };
    const currentConfig = {agent:{max_task_tokens:-1}, multi_agent:{tool_search_enable:true, reduction_enable:true}};
    const ctx = vm.createContext({currentConfig, document:{getElementById:id=>elements[id]}, settingsT:(_key,fallback)=>fallback});
    for (const name of ['applyTokenOptimizationSettings', 'readTaskTokenBudget', 'readTokenOptimizationSettings']) {
        vm.runInContext(settings.match(new RegExp(`function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\}`))[0], ctx);
    }
    ctx.applyTokenOptimizationSettings(currentConfig);
    assert.equal(ctx.readTaskTokenBudget(), -1);
    assert.equal(ctx.readTokenOptimizationSettings().tool_search_enable, true);
    elements['eino-tool-search-enable'].checked = false;
    assert.equal(ctx.readTokenOptimizationSettings().tool_search_enable, false);
    elements['agent-max-task-tokens'].value = '0';
    assert.equal(ctx.readTaskTokenBudget(), 1000000);
    elements['agent-max-task-tokens'].value = '250000';
    assert.equal(ctx.readTaskTokenBudget(), 250000);
    for (const invalid of ['-2', '1.5', 'not-a-number']) {
        elements['agent-max-task-tokens'].value = invalid;
        assert.throws(()=>ctx.readTaskTokenBudget(), /预算/);
    }
    delete elements['eino-reduction-enable'];
    assert.equal(ctx.readTokenOptimizationSettings().reduction_enable, true);
});
