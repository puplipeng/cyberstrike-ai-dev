const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const ssh=require('./ssh.js'),attack='<img src=x onerror="alert(1)">';
test('SSH connection and remote filename renderers escape all untrusted strings',()=>{
 const cards=ssh.cards([{id:attack,name:attack,host:attack,username:attack,port:22}],'');
 const rows=ssh.fileRows([{name:attack,size:attack,mode:attack,directory:false}]);
 for(const html of [cards,rows]){assert.ok(!html.includes('<img'));assert.ok(html.includes('&lt;img'))}
});
test('SSH WebSocket URL never contains login tokens and path input remains literal',()=>{
 assert.equal(ssh.socketURL('https://example.test','ssh_test'),'wss://example.test/api/ssh/connections/ssh_test/terminal');
 assert.ok(!ssh.socketURL('http://localhost','x?token=secret').includes('?'));
 assert.equal(ssh.join('/','a b.txt'),'/a b.txt');assert.equal(ssh.join('.','file'), './file');
});
test('SSH wiring, cleanup and both translation sets are present',()=>{
 const html=fs.readFileSync(path.join(__dirname,'../../templates/index.html'),'utf8');
 assert.ok(html.includes('id="ssh-panel"'));assert.ok(html.includes('ssh.js?v=20260829-fixes1'));assert.ok(html.includes('router.js?v=20260901-ghleak1'));
 const router=fs.readFileSync(path.join(__dirname,'router.js'),'utf8');assert.ok(router.includes('SSHManager.init()'));assert.ok(router.includes('SSHManager.cleanup()'));
 const auth=fs.readFileSync(path.join(__dirname,'auth.js'),'utf8');assert.ok(auth.includes('SSHManager.cleanup()'));
 for(const lang of ['zh-CN','en-US']) {
  const data=JSON.parse(fs.readFileSync(path.join(__dirname,'../i18n',lang+'.json'),'utf8'));
  for(const key of Object.keys(ssh.words))assert.ok(data.ssh[key],key);
 }
});

// Execute the actual module in a minimal DOM; no browser or remote data is used.
const vm=require('node:vm'), source=fs.readFileSync(path.join(__dirname,'ssh.js'),'utf8');
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); };

function harness() {
    const nodes = new Map(), requests = [], pending = new Map();
    class Node {
        constructor(id) { this.id = id; this.listeners = {}; this.value = ''; this.textContent = ''; this.dataset = {}; this.hidden = false; this._html = ''; }
        set innerHTML(html) {
            this._html = html;
            if (this.id === 'ssh-panel') {
                for (const match of html.matchAll(/id="([^"]+)"/g)) nodes.set(match[1], new Node(match[1]));
            }
        }
        get innerHTML() { return this._html; }
        addEventListener(name, fn) { this.listeners[name] = fn; }
        setAttribute(name, value) { this[name] = value; }
        querySelector(selector) { return nodes.get(selector.slice(1)); }
        click() {}
    }
    for (const id of ['ssh-panel', 'ssh-mode-web', 'ssh-mode-ssh']) nodes.set(id, new Node(id));
    const webContent = new Node('web'), addWeb = new Node('add-web');
    const document = {
        getElementById: id => nodes.get(id) || null,
        querySelector: selector => selector.includes('webshell-page-content') ? webContent : addWeb,
        createElement: () => new Node('a')
    };
    const response = data => ({ ok: true, json: async () => data, blob: async () => new Blob(['canary']) });
    const apiFetch = async (path, options) => {
        requests.push({path, method: options.method || 'GET'});
        if (path === '/api/ssh/connections') return response({items:[{id:'ssh_fixture',name:'Fixture',username:'fixture',host:'127.0.0.1',port:22,fingerprint:'SHA256:fixture'}]});
        if (path.includes('/files/list')) {
            const dir = new URL(path, 'http://test.invalid').searchParams.get('path');
            if (pending.has(dir)) return await pending.get(dir);
            return response({path:dir,items:[{name:'report.txt',directory:false,size:3,mode:'-rw-------'}]});
        }
        if (path.includes('/files/upload') && pending.has('upload')) return await pending.get('upload');
        return response({});
    };
    const context = { module:{exports:{}}, window:{addEventListener(){},location:{origin:'http://test.invalid'}}, document,
        hasPermission:()=>true, apiFetch, AbortController, URL:{createObjectURL:()=>'blob:canary',revokeObjectURL(){}}, setTimeout:fn=>fn(), Blob };
    vm.runInNewContext(source, context, {filename:'ssh.js'});
    const manager = context.module.exports;
    const node = id => nodes.get('ssh-'+id);
    async function start() {
        manager.show(true); await settle();
        node('connections').listeners.click({target:{closest:()=>({dataset:{sshSelect:'ssh_fixture'}})}});
        node('path').value='/safe';
        node('files').listeners.submit({preventDefault(){}});
        await settle();
    }
    function deferredDirectory(dir) {
        let resolve;
        pending.set(dir,new Promise(r=>resolve=r));
        return () => resolve(response({path:dir,items:[{name:dir.slice(1)+'.txt',directory:false,size:3,mode:'-rw-------'}]}));
    }
    function browse(dir) { node('path').value=dir;node('files').listeners.submit({preventDefault(){}}); }
    return {manager,node,start,browse,requests,deferredDirectory,pending};
}

test('displayed filename must remain bound to the directory that produced its listing', async () => {
    const h=harness(); await h.start();
    assert.match(h.node('file-results').innerHTML,/report\.txt/);
    // The user edits the path input without submitting it; the old listing remains visible.
    h.node('path').value='/other';
    h.node('file-results').listeners.click({target:{closest:()=>({dataset:{sshFile:'report.txt',directory:'0'}})}});
    await settle();
    const download=h.requests.find(r=>r.path.includes('/files/download'));
    const actual=new URL(download.path,'http://test.invalid').searchParams.get('path');
    assert.equal(actual,'/safe/report.txt',`clicked /safe/report.txt but requested ${actual}`);
});

test('a slower earlier directory response must not replace the latest navigation', async () => {
    const h=harness(); await h.start();
    const first=h.deferredDirectory('/first'),second=h.deferredDirectory('/second');
    h.browse('/first'); h.browse('/second');
    second(); await settle();
    assert.equal(h.node('path').value,'/second');
    first(); await settle();
    assert.equal(h.node('path').value,'/second','older listing response overwrote newer navigation');
});
test('SSH invalidates old rows while editing paths and after failed navigation',async()=>{
 const h=harness();await h.start();
 h.node('path').value='/edited';h.node('path').listeners.input();
 const click=()=>h.node('file-results').listeners.click({target:{closest:()=>({dataset:{sshFile:'report.txt',directory:'0'}})}});
 click();h.node('upload').files=[{name:'canary.txt',size:3}];h.node('upload').listeners.change();await settle();
 assert.equal(h.node('file-results').innerHTML,'');
 assert.equal(h.requests.filter(r=>/\/files\/(download|upload)/.test(r.path)).length,0);
 h.pending.set('/missing',Promise.resolve({ok:false,json:async()=>({error:'missing directory'})}));
 h.browse('/missing');await settle();click();await settle();
 assert.equal(h.node('file-results').innerHTML,'');
 assert.equal(h.requests.filter(r=>r.path.includes('/files/download')).length,0);
});
test('SSH cleanup prevents a pending directory response from restoring rows',async()=>{
 const h=harness();await h.start();const finish=h.deferredDirectory('/pending');
 h.browse('/pending');h.manager.cleanup();finish();await settle();
 assert.equal(h.node('file-results').innerHTML,'');
});
test('SSH upload uses the confirmed destination without restoring an older navigation',async()=>{
 const h=harness();await h.start();const finish=h.deferredDirectory('upload');
 h.node('upload').files=[{name:'canary.txt',size:3}];h.node('upload').listeners.change();
 await settle();h.browse('/second');await settle();finish();await settle();
 const request=h.requests.find(r=>r.path.includes('/files/upload'));
 assert.equal(new URL(request.path,'http://test.invalid').searchParams.get('path'),'/safe/canary.txt');
 assert.equal(h.node('path').value,'/second');
});
