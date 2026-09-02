/* SSH credentials are submitted only from the editor and never kept in list state. */
const SSHManager = (() => {
    const words={add:'添加 SSH 连接',refresh:'刷新',empty:'暂无 SSH 连接',choose:'选择连接后可核验指纹、打开终端或管理文件。',name:'名称',host:'主机 IP / 域名',port:'端口',username:'用户名',auth:'认证方式',password:'密码',key:'私钥',passphrase:'私钥口令（可选）',save:'保存',cancel:'取消',edit:'编辑',remove:'删除',probe:'核验主机指纹',test:'测试登录',connect:'打开终端',disconnect:'断开终端',files:'SFTP 文件',path:'远程目录',browse:'打开目录',upload:'上传新文件',parent:'上级目录',size:'字节',mode:'权限',untrusted:'尚未确认主机指纹',fingerprint:'已确认指纹',trust:'确认信任此指纹',trustHint:'请通过服务器控制台或管理员独立核对下方 SHA256 指纹；确认后才会发送登录凭据。',credentialHint:'编辑时凭据留空表示保留原凭据。私钥只在保存时发送，服务端加密存储，不会回显。',hint:'连接由创建者和具有全局 WebShell 权限的账号管理。远程操作需要管理权限。单文件最大 16 MiB；上传不覆盖同名文件。',deleteConfirm:'删除此 SSH 连接并断开相关会话？远程文件不会删除。',saved:'连接已保存',trusted:'主机指纹已确认',tested:'SSH 登录成功',closed:'终端已断开',working:'正在处理…',terminalMissing:'终端组件未加载，请刷新页面',uploadDone:'上传完成',tooLarge:'单文件最大 16 MiB',truncated:'目录只显示前 1000 项',failure:'操作失败',changed:'连接已切换，请重试'};
    const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const t=key=>{const value=typeof window!=='undefined'&&typeof window.t==='function'?window.t('ssh.'+key):'';return value&&value!=='ssh.'+key?value:(words[key]||key)};
    const can=p=>typeof hasPermission==='function'&&hasPermission(p);
    const el=id=>document.getElementById('ssh-'+id);
    const join=(dir,name)=>(dir==='/'?'':dir.replace(/\/+$/,''))+'/'+name;
    const socketURL=(origin,id)=>origin.replace(/^http/,'ws')+'/api/ssh/connections/'+encodeURIComponent(id)+'/terminal';
    const button=(id,key)=>'<button type="button" id="ssh-'+id+'" class="btn-secondary">'+esc(t(key||id))+'</button>';
    function cards(items,selected) {
        return items.map(d=>'<button class="ssh-connection '+(d.id===selected?'selected':'')+'" data-ssh-select="'+esc(d.id)+'"><strong>'+esc(d.name)+'</strong><span>'+esc(d.username)+'@'+esc(d.host)+':'+esc(d.port)+'</span></button>').join('')||'<p>'+esc(t('empty'))+'</p>';
    }
    function fileRows(items) {
        return items.map(f=>'<tr><td><button class="btn-ghost" data-ssh-file="'+esc(f.name)+'" data-directory="'+(f.directory?'1':'0')+'">'+(f.directory?'📁 ':'')+esc(f.name)+'</button></td><td>'+esc(f.size)+'</td><td>'+esc(f.mode)+'</td></tr>').join('');
    }
    words.browseFirst='请先打开目标目录，再上传文件';
    words.truncated='目录达到条目或数据量上限，仅显示部分结果';
    let root,items=[],selected=null,shown=false,seq=0,connectionSeq=0,directorySeq=0,listing=null,socket,terminal,resizeObserver,fit,controller,probeResult;
    const current=()=>items.find(d=>d.id===selected);
    function message(value,error=false){if(el('message')){el('message').textContent=value||'';el('message').className=error?'ssh-error':'ssh-note'}}
    async function request(path,options={}) {
        const response=await apiFetch('/api/ssh'+path,{...options,signal:controller?.signal});
        if(!response.ok){const data=await response.json().catch(()=>({}));throw new Error(data.error||t('failure'))}
        return response;
    }
    const json=async(path,options={})=>(await request(path,{...options,headers:{'Content-Type':'application/json',...options.headers}})).json();
    const post=(path,body={})=>json(path,{method:'POST',body:JSON.stringify(body)});
    async function run(fn){const mine=seq;message(t('working'));try{await fn();if(mine===seq&&el('message').textContent===t('working'))message('')}catch(e){if(e.name!=='AbortError'&&mine===seq)message(e.message,true)}}
    function invalidateFiles() {
        directorySeq++;listing=null;
        if(el('file-results'))el('file-results').innerHTML='';
    }
    function renderDetail() {
        const d=current();probeResult=null;el('trust-panel').hidden=true;
        el('detail').hidden=!d;el('choose').hidden=!!d;
        invalidateFiles();
        if(!d)return;
        el('name').textContent=d.name;el('address').textContent=d.username+'@'+d.host+':'+d.port;
        el('fingerprint').textContent=d.fingerprint||t('untrusted');
        for(const id of ['connect','test'])if(el(id))el(id).disabled=!d.fingerprint;
        el('path').value='.';
    }
    async function refresh(preferred) {
        if(!root)return;
        const mine=seq,result=await json('/connections');if(mine!==seq||!root)return;
        items=result.items||[];if(preferred)selected=preferred;
        if(!current()){disconnect();selected=null}
        el('connections').innerHTML=cards(items,selected);renderDetail();
    }
    function init() {
        if(root)return;
        root=el('panel');if(!root)return;
        controller=new AbortController();const write=can('webshell:write');
        const formFields=['name','host','port','username'].map(k=>'<label>'+esc(t(k))+'<input id="ssh-edit-'+k+'" required '+(k==='port'?'type="number" min="1" max="65535" value="22"':'maxlength="200"')+'></label>').join('');
        root.innerHTML=[
            '<div class="ssh-toolbar">'+(write?button('add'):'')+button('refresh')+'</div><p class="ssh-note">'+esc(t('hint'))+'</p><p id="ssh-message" role="status"></p>',
            '<div class="ssh-layout"><aside id="ssh-connections"></aside><div class="ssh-workspace"><p id="ssh-choose">'+esc(t('choose'))+'</p><section id="ssh-detail" hidden>',
            '<h3 id="ssh-name"></h3><p id="ssh-address"></p><p>'+esc(t('fingerprint'))+': <code id="ssh-fingerprint"></code></p>',
            write?'<div class="ssh-toolbar">'+['edit','probe','test','connect','disconnect'].map(k=>button(k)).join('')+'</div>':'',
            can('webshell:delete')?button('remove'):'',
            '<div id="ssh-trust-panel" class="ssh-trust" hidden><p>'+esc(t('trustHint'))+'</p><code id="ssh-observed"></code>'+button('trust')+'</div><div id="ssh-terminal" class="ssh-terminal" hidden></div>',
            write?'<h3>'+esc(t('files'))+'</h3><form id="ssh-files" class="ssh-toolbar"><label>'+esc(t('path'))+'<input id="ssh-path" value="." maxlength="4096"></label><button class="btn-secondary">'+esc(t('browse'))+'</button>'+button('parent')+'<label class="btn-secondary">'+esc(t('upload'))+'<input id="ssh-upload" type="file" hidden></label></form><table class="ssh-files"><thead><tr><th>'+esc(t('name'))+'</th><th>'+esc(t('size'))+'</th><th>'+esc(t('mode'))+'</th></tr></thead><tbody id="ssh-file-results"></tbody></table>':'<div id="ssh-file-results"></div><input id="ssh-path" hidden>',
            '</section></div></div><dialog id="ssh-editor"><form id="ssh-form"><h3>'+esc(t('add'))+'</h3><div class="ssh-fields">'+formFields,
            '<label>'+esc(t('auth'))+'<select id="ssh-edit-auth"><option value="password">'+esc(t('password'))+'</option><option value="key">'+esc(t('key'))+'</option></select></label>',
            '<label id="ssh-password-field">'+esc(t('password'))+'<input id="ssh-edit-password" type="password" autocomplete="new-password" maxlength="16384"></label>',
            '<label id="ssh-key-field" hidden>'+esc(t('key'))+'<textarea id="ssh-edit-key" rows="7" spellcheck="false" maxlength="65536"></textarea></label>',
            '<label id="ssh-passphrase-field" hidden>'+esc(t('passphrase'))+'<input id="ssh-edit-passphrase" type="password" autocomplete="new-password" maxlength="16384"></label></div>',
            '<p class="ssh-note">'+esc(t('credentialHint'))+'</p><p id="ssh-form-error" class="ssh-error" role="alert"></p><div class="ssh-toolbar"><button id="ssh-save" class="btn-primary">'+esc(t('save'))+'</button>'+button('cancel')+'</div></form></dialog>'
        ].join('');
        el('add')?.addEventListener('click',()=>editor());
        el('refresh').addEventListener('click',()=>run(()=>refresh()));
        el('edit')?.addEventListener('click',()=>editor(current()));
        el('cancel').addEventListener('click',()=>el('editor').close());
        el('editor').addEventListener('close',event=>clearCredentials(event.currentTarget));
        el('edit-auth').addEventListener('change',authFields);
        el('form').addEventListener('submit',save);
        el('connections').addEventListener('click',event=>{
            const b=event.target.closest('[data-ssh-select]');if(!b)return;
            seq++;disconnect();selected=b.dataset.sshSelect;el('connections').innerHTML=cards(items,selected);renderDetail();message('');
        });
        el('probe')?.addEventListener('click',()=>run(async()=>{
            const d=current(),mine=seq,r=await post('/connections/'+d.id+'/probe');if(mine!==seq)return;
            probeResult={...r,id:d.id};el('observed').textContent=r.fingerprint;el('trust-panel').hidden=false;
        }));
        el('trust').addEventListener('click',()=>run(async()=>{
            const p=probeResult;if(!p||p.id!==selected)throw new Error(t('changed'));
            await post('/connections/'+p.id+'/trust',{fingerprint:p.fingerprint,revision:p.revision});await refresh();message(t('trusted'));
        }));
        el('test')?.addEventListener('click',()=>run(async()=>{await post('/connections/'+selected+'/test');message(t('tested'))}));
        el('remove')?.addEventListener('click',()=>{if(window.confirm(t('deleteConfirm')))run(async()=>{
            const d=current();await json('/connections/'+d.id,{method:'DELETE',body:JSON.stringify({revision:d.revision})});disconnect();await refresh();
        })});
        el('connect')?.addEventListener('click',()=>run(connect));
        el('disconnect')?.addEventListener('click',()=>{disconnect();message(t('closed'))});
        el('files')?.addEventListener('submit',e=>{e.preventDefault();run(()=>listFiles())});
        el('path').addEventListener('input',invalidateFiles);
        el('parent')?.addEventListener('click',()=>{el('path').value=join(listing?.path??el('path').value,'..');run(()=>listFiles())});
        el('file-results').addEventListener('click',e=>{
            const b=e.target.closest('[data-ssh-file]');if(!b)return;
            const directory=listing;if(!directory||directory.id!==selected)return;
            const file=directory.entries.get(b.dataset.sshFile);if(!file)return;
            const target=join(directory.path,file.name);
            if(file.directory){el('path').value=target;run(()=>listFiles())}else run(()=>download(target,directory.id));
        });
        el('upload')?.addEventListener('change',()=>run(upload));
        window.addEventListener('beforeunload',cleanup);
    }
    function show(value) {
        init();shown=value;root.hidden=!value;
        document.querySelector('#page-webshell .webshell-page-content').hidden=value;
        document.querySelector('#page-webshell [onclick="showAddWebshellModal()"]').hidden=value;
        el('mode-web').setAttribute('aria-selected',String(!value));el('mode-ssh').setAttribute('aria-selected',String(value));
        if(value){controller=new AbortController();run(()=>refresh())}else cleanup();
    }
    function clearCredentials(dialog=el('editor')){for(const k of ['password','key','passphrase']){const field=dialog?.querySelector('#ssh-edit-'+k);if(field)field.value=''}}
    function authFields(){const key=el('edit-auth').value==='key';el('password-field').hidden=key;el('key-field').hidden=!key;el('passphrase-field').hidden=!key}
    function editor(d) {
        el('form').reset();clearCredentials();el('form').dataset.id=d?.id||'';el('form').dataset.revision=String(d?.revision||0);
        for(const k of ['name','host','port','username'])el('edit-'+k).value=d?.[k]??(k==='port'?22:'');
        el('edit-auth').value=d?.auth_type||'password';authFields();el('form-error').textContent='';el('editor').showModal();
    }
    async function save(event) {
        event.preventDefault();const id=el('form').dataset.id,mine=seq;
        const data={name:el('edit-name').value,host:el('edit-host').value,port:Number(el('edit-port').value),username:el('edit-username').value,auth_type:el('edit-auth').value,revision:Number(el('form').dataset.revision)};
        const secret=data.auth_type==='key'?el('edit-key').value:el('edit-password').value;
        if(!id||secret)data.credential=data.auth_type==='key'?{private_key:secret,passphrase:el('edit-passphrase').value}:{password:secret};
        el('save').disabled=true;
        try {
            const d=await json('/connections'+(id?'/'+id:''),{method:id?'PUT':'POST',body:JSON.stringify(data)});
            if(mine!==seq||!root)return;
            clearCredentials();el('editor').close();disconnect();await refresh(d.id);message(t('saved'));
        } catch(e){if(mine===seq&&el('form-error'))el('form-error').textContent=e.message}finally{if(el('save'))el('save').disabled=false}
    }
    async function listFiles(path=el('path')?.value) {
        if(!root||!selected)return;
        invalidateFiles();
        const mine=seq,id=selected,navigation=directorySeq;
        try {
            const r=await json('/connections/'+id+'/files/list?path='+encodeURIComponent(path));
            if(mine!==seq||id!==selected||navigation!==directorySeq||!root)return;
            listing={id,path:r.path,entries:new Map(r.items.map(file=>[file.name,file]))};
            el('path').value=r.path;el('file-results').innerHTML=fileRows(r.items);message(r.truncated?t('truncated'):'');
        } catch(e) {
            if(mine===seq&&id===selected&&navigation===directorySeq)throw e;
        }
    }
    async function download(path,id) {
        const response=await request('/connections/'+id+'/files/download?path='+encodeURIComponent(path));
        const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');
        a.href=url;a.download=path.split('/').pop()||'download';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
    async function upload() {
        const file=el('upload').files[0];el('upload').value='';if(!file)return;
        if(file.size>16*1024*1024)throw new Error(t('tooLarge'));
        const name=file.name;if(!name||name.includes('/')||name.includes('\\'))throw new Error(t('failure'));
        const directory=listing,mine=seq,navigation=directorySeq;
        if(!directory||directory.id!==selected||el('path').value!==directory.path)throw new Error(t('browseFirst'));
        await request('/connections/'+directory.id+'/files/upload?path='+encodeURIComponent(join(directory.path,name)),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
        if(mine!==seq||directory.id!==selected||navigation!==directorySeq)return;
        await listFiles(directory.path);if(mine===seq&&directory.id===selected)message(t('uploadDone'));
    }
    function disconnect() {
        connectionSeq++;const old=socket;socket=null;if(old){old.onclose=null;old.close()}
        resizeObserver?.disconnect();resizeObserver=null;terminal?.dispose();terminal=null;fit=null;
        if(el('terminal')){el('terminal').innerHTML='';el('terminal').hidden=true}
    }
    async function connect() {
        disconnect();const mine=connectionSeq,id=selected;
        if(typeof Terminal==='undefined')throw new Error(t('terminalMissing'));
        await post('/connections/'+id+'/terminal-ticket');
        if(mine!==connectionSeq||id!==selected||!shown)return;
        el('terminal').hidden=false;
        terminal=new Terminal({cursorBlink:true,scrollback:3000,fontSize:13,theme:{background:'#111827',foreground:'#e5e7eb'}});
        if(typeof FitAddon!=='undefined'){fit=new (FitAddon.FitAddon||FitAddon)();terminal.loadAddon(fit)}
        terminal.open(el('terminal'));fit?.fit();
        const ws=new WebSocket(socketURL(window.location.origin,id));socket=ws;ws.binaryType='arraybuffer';
        const resize=()=>{if(mine!==connectionSeq)return;fit?.fit();if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({type:'resize',cols:terminal.cols,rows:terminal.rows}))};
        ws.onopen=()=>{if(mine!==connectionSeq){ws.close();return}message('');terminal.focus();resize()};
        ws.onmessage=e=>{if(mine===connectionSeq)terminal.write(new Uint8Array(e.data))};
        ws.onerror=()=>{if(mine===connectionSeq)message(t('failure'),true)};
        ws.onclose=()=>{if(mine===connectionSeq){message(t('closed'));disconnect()}};
        terminal.onData(value=>{
            if(ws.readyState!==WebSocket.OPEN)return;if(ws.bufferedAmount>1024*1024){ws.close();return}
            const bytes=new TextEncoder().encode(value);for(let i=0;i<bytes.length;i+=16384)ws.send(bytes.slice(i,i+16384));
        });
        resizeObserver=new ResizeObserver(resize);resizeObserver.observe(el('terminal'));
    }
    function cleanup(){
        seq++;controller?.abort();controller=new AbortController();disconnect();
        invalidateFiles();
        if(el('editor')?.open)el('editor').close();
        items=[];selected=null;probeResult=null;
        if(root){root.innerHTML='';root=null}
    }
    function enter(){init();if(shown)run(()=>refresh())}
    return {init:enter,show,cleanup,words,cards,fileRows,socketURL,join};
})();
if(typeof module!=='undefined')module.exports=SSHManager;
if(typeof window!=='undefined')window.SSHManager=SSHManager;
