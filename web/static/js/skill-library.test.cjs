const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const library=require('./skill-library.js');
const attack='<img src=x onerror="alert(1)">';
test('library cards escape source text, metadata, identifiers and errors',()=>{
 const html=library.card({id:attack,title:attack,path:attack,root:attack,snippet:attack,error:attack,kind:'poc',review:'unreviewed',state:'error',metadata:{cves:[attack]},matches:['semantic']});
 assert.ok(!html.includes('<img'));assert.ok(html.includes('&lt;img'));assert.ok(html.includes('PoC'));assert.ok(!html.includes('data-sl-execute'));
});
test('review actions are explicit, permission-gated and keep complete metadata',()=>{
 const d={id:'doc-1',title:'Example',kind:'reference',review:'unreviewed',revision:7,metadata:{products:['demo']}};
 assert.ok(!library.card(d).includes('data-sl-review'));
 const html=library.card(d,true);assert.ok(html.includes('data-sl-review="reviewed"'));assert.ok(html.includes('data-sl-review="rejected"'));
 assert.deepEqual(library.reviewBody(d,'reviewed'),{title:'Example',kind:'reference',review:'reviewed',revision:7,metadata:{products:['demo']}});
});
test('detail dialog uses a dedicated vertical scroll container',()=>{
 const css=fs.readFileSync(path.join(__dirname,'../css/skill-library.css'),'utf8');
 assert.match(css,/\.sl-dialog-body\{[^}]*overflow-y:auto/);assert.match(css,/#page-skill-library dialog\{[^}]*overflow:hidden/);
});
test('library list owns a vertical scrolling page-content container',()=>{
 const css=fs.readFileSync(path.join(__dirname,'../css/skill-library.css'),'utf8');
 assert.match(css,/\.sl-page-content\{[^}]*overflow-y:auto/);
 assert.equal(library.words.reviewed,'已通过（可用）');assert.match(library.words.reviewNote,/Agent/);
});
test('library source snapshots are plain text and review does not imply execution',()=>{
 const html=library.detailHTML({document:{id:'a',title:attack,hash:'a',content:attack,kind:'reference',review:'unreviewed',metadata:{source_url:'javascript:alert(1)',notes:attack}},links:[],source_current:false});
 assert.ok(!html.includes('<img'));assert.ok(!html.includes('href="javascript:'));assert.ok(html.includes('disabled'));assert.ok(html.includes('原文件已变化'));
});
test('CVE preview shows the full count and escapes derived fields',()=>{
 const detail={document:{kind:'reference',detected_cve_count:51,metadata:{detected_cves:[]}},links:[],source_current:true};
 detail.document.metadata.detected_cves=Array.from({length:50},(_,i)=>'CVE-2099-'+(40000+i));
 let html=library.detailHTML(detail);
 assert.ok(html.includes('识别总数: 51'));assert.ok(html.includes('检索覆盖全部'));assert.ok(html.includes('CVE-2099-40049'));assert.ok(!html.includes('CVE-2099-40050'));
 detail.document.detected_cve_count=attack;detail.document.metadata.detected_cves=[attack];
 html=library.detailHTML(detail);assert.ok(!html.includes('<img'));assert.ok(html.includes('&lt;img'));
 delete detail.document.detected_cve_count;
 assert.ok(library.detailHTML(detail).includes('识别总数: 1'));
});
test('only manual relationships have remove controls',()=>{
 const links=[{skill_id:'s',resource_id:'r',skill_title:attack,resource_title:'ref',note:attack,source:'package'}];
 assert.ok(!library.linksHTML(links,true).includes('data-sl-unlink'));
 links[0].source='manual';assert.ok(library.linksHTML(links,true).includes('data-sl-unlink'));
 assert.ok(!library.linksHTML(links,false).includes('data-sl-unlink'));assert.ok(!library.linksHTML(links,true).includes('<img'));
});
test('query encoding preserves literal input and all filters',()=>{
 const input={q:'CVE-2021-44228 & 中文 # %',kind:'poc',review:'reviewed',cve:'CVE-2021-44228',product:'a+b',page:2};
 const p=new URLSearchParams(library.params(input));for(const key of Object.keys(input))assert.equal(p.get(key),String(input[key]));
 assert.deepEqual(library.split('a, b，c\n\n d'),['a','b','c','d']);
});
test('library is wired to routing, permission visibility and bilingual resources',()=>{
 const web=path.join(__dirname,'../..');
 const html=fs.readFileSync(path.join(web,'templates/index.html'),'utf8');
 assert.ok(html.includes('id="page-skill-library"'));assert.ok(html.includes('/static/js/skill-library.js?v=5'));assert.ok(html.includes('/static/css/skill-library.css?v=3'));
 const router=fs.readFileSync(path.join(__dirname,'router.js'),'utf8');assert.ok(router.includes("case 'skill-library':"));
 const auth=fs.readFileSync(path.join(__dirname,'auth.js'),'utf8');assert.ok(auth.includes("'skill-library': 'skills:read'"));
 for(const language of ['zh-CN','en-US']){const data=JSON.parse(fs.readFileSync(path.join(__dirname,'../i18n',language+'.json'),'utf8'));for(const key of Object.keys(library.words))assert.ok(data.skillLibrary[key],key);}
});
test('primary library separates general knowledge from skills and PoCs',()=>{
 const source=fs.readFileSync(path.join(__dirname,'skill-library.js'),'utf8');
 assert.match(source,/kind:'skill'/);
 assert.match(source,/options\(\['skill','poc'\]\)/);
 assert.ok(!source.includes("options(['skill','poc','reference'])"));
 assert.match(library.words.knowledgeNotice,/知识管理/);
});
