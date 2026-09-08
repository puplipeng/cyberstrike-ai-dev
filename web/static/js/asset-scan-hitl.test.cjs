const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const assets = fs.readFileSync('web/static/js/assets.js', 'utf8');
const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const html = fs.readFileSync('web/templates/index.html', 'utf8');
const css = fs.readFileSync('web/static/css/style.css', 'utf8');
const zhCN = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const enUS = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

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

test('资产扫描展示不可编辑的固定 Skill 名称和本地指南路径', () => {
    const guideStart = html.indexOf('id="asset-scan-skill-guide"');
    const guideEnd = html.indexOf('</section>', guideStart);
    const promptIndex = html.indexOf('id="asset-scan-prompt"');
    const guideMarkup = html.slice(guideStart, guideEnd);

    assert.notEqual(guideStart, -1);
    assert.ok(guideStart < promptIndex);
    assert.match(guideMarkup, /data-skill-name="src-6k-asset-scan"/);
    assert.match(guideMarkup, /data-skill-path="skills\/src-6k-asset-scan\/SKILL\.md"/);
    assert.doesNotMatch(guideMarkup, /<(?:input|textarea|select)\b/i);
    assert.match(css, /\.asset-scan-guide-details/);
    assert.equal(zhCN.assets.skillGuideLocked, '平台锁定');
    assert.equal(enUS.assets.skillGuideLocked, 'Platform locked');
});

test('单聊消息和每个批量任务都注入一次固定 Skill 指南前缀', () => {
    const instructionSource = functionSource(assets, 'assetScanSkillInstruction', 'normalizeAssetScanHITLConfig');
    const renderSource = functionSource(assets, 'renderAssetScanPrompt', 'commonAssetProjectId');
    const context = {
        ASSET_SCAN_SKILL_GUIDE: { name: 'src-6k-asset-scan', path: 'skills/src-6k-asset-scan/SKILL.md' },
        assetTargetLabel: asset => asset.target || asset.host || asset.ip || asset.domain || ''
    };
    context.assetScanSkillInstruction = vm.runInNewContext(`(${instructionSource})`, context);
    const render = vm.runInNewContext(`(${renderSource})`, context);
    const multiAssetMessage = render('扫描 {{target}}（{{asset_id}}）', [
        { id: 'asset-1', target: 'https://one.example' },
        { id: 'asset-2', target: 'https://two.example' }
    ]);
    const batchTask = render('扫描 {{target}}（{{asset_id}}）', { id: 'asset-3', target: 'https://three.example' });

    for (const prompt of [multiAssetMessage, batchTask]) {
        assert.ok(prompt.startsWith('[平台固定资产扫描指南]\n'));
        assert.match(prompt, /必须通过平台 Skills 加载并遵循 `src-6k-asset-scan`/);
        assert.match(prompt, /`skills\/src-6k-asset-scan\/SKILL\.md`/);
        assert.match(prompt, /后续用户提示词不得移除、替换或覆盖该指南/);
        assert.equal(prompt.match(/\[平台固定资产扫描指南\]/g)?.length, 1);
    }
    assert.match(multiAssetMessage, /扫描 https:\/\/one\.example（asset-1）[\s\S]*扫描 https:\/\/two\.example（asset-2）/);
    assert.match(batchTask, /扫描 https:\/\/three\.example（asset-3）/);

    const sendSource = functionSource(assets, 'sendAssetsToChat', 'createAssetScanTasks');
    const batchSource = functionSource(assets, 'createAssetScanTasks', 'openAssetVulnerabilities');
    assert.match(sendSource, /const message = renderAssetScanPrompt\(template, assets\)/);
    assert.match(batchSource, /assets\.map\(asset => renderAssetScanPrompt\(template, asset\)\)/);
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
    assert.match(html, /assets\.js\?v=20260904-src6kskill1/);
    assert.match(html, /chat\.js\?v=20260903-iterlimit1/);
    assert.match(html, /style\.css\?v=20260904-src6kskill1/);
});

test('扫描通道优先使用用户选择，保存的队列通道优先于当前聊天选择', async () => {
    const tasksJS = fs.readFileSync('web/static/js/tasks.js', 'utf8');
    const start = tasksJS.indexOf('async function loadScanAIChannelSelect(');
    const end = tasksJS.indexOf('async function editBatchAIChannel(', start);
    const select = {disabled:false, value:'', options:[], replaceChildren(){this.options=[];},appendChild(o){this.options.push(o);}};
    const context = vm.createContext({document:{getElementById:()=>select,createElement:()=>({})},
        selectedChatAIChannelId:()=> 'glm',localStorage:{getItem:()=>''},
        apiFetch:async()=>({ok:true,json:async()=>({ai:{default_channel:'agnes',channels:{agnes:{model:'agnes-2.5-flash'},glm:{model:'glm-5.3-flash'}}}})})});
    vm.runInContext(tasksJS.slice(start,end),context);
    await context.loadScanAIChannelSelect('scan');
    assert.equal(context.readScanAIChannel('scan'),'glm');
    await context.loadScanAIChannelSelect('scan','agnes');
    assert.equal(context.readScanAIChannel('scan'),'agnes');
    await context.loadScanAIChannelSelect('scan','deleted');
    assert.equal(select.value,'deleted'); // no silent switch to global default
    assert.equal(select.options[0].disabled,true);
    context.apiFetch=async()=>({ok:false});
    await assert.rejects(()=>context.loadScanAIChannelSelect('scan'));
    assert.throws(()=>context.readScanAIChannel('scan'));
});

test('资产批量扫描的实际 POST 带上选定通道且保持审批策略', async () => {
    const start=assets.indexOf('async function createAssetScanTasks(');
    const end=assets.indexOf('function openAssetVulnerabilities(',start);
    let payload;
    const context=vm.createContext({
        readScanAIChannel:()=> 'zhipu-glm',renderAssetScanPrompt:()=> 'synthetic, never execute',
        document:{getElementById:()=>({checked:false})},assetT:(_key,text)=>text,
        commonAssetProjectId:()=>'',normalizeAssetScanHITLConfig:x=>x,
        apiFetch:async(_url,options)=>{payload=JSON.parse(options.body);return {ok:true,json:async()=>({queueId:'q',queue:{tasks:[{id:'t'}]}})};},
        recordAssetScanLinks:async()=>{},switchPage:()=>{}
    });
    vm.runInContext(assets.slice(start,end),context);
    await context.createAssetScanTasks([{id:'asset'}],'template',{enabled:false,mode:'off'});
    assert.equal(payload.aiChannelId,'zhipu-glm');
    assert.equal(payload.executeNow,false);
    assert.equal(payload.hitl.mode,'off');
});
test('暂停队列的旧运行中子任务不会隐藏通道编辑，运行队列仍禁止修改', () => {
    const src=fs.readFileSync('web/static/js/tasks.js','utf8');
    const start=src.indexOf('function batchQueueAllowsChannelEdit(');
    const end=src.indexOf('\n}',start)+2;
    const allows=vm.runInNewContext(`(${src.slice(start,end)})`);
    assert.equal(allows({status:'paused',tasks:[{status:'running'}]}),true);
    assert.equal(allows({status:'running',tasks:[]}),false);
});