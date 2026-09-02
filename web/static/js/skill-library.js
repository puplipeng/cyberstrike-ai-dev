/* Search results are evidence snippets, never instructions to execute. */
const SkillLibrary = (() => {
    const words = {
        title:'技能与 PoC 库', subtitle:'这里管理可加载的技能和可检索的 PoC；方法论、经验手册和索引指南统一放在知识管理。',
        refresh:'刷新', index:'增量扫描与索引', rebuild:'全量重建索引', rebuildConfirm:'全量重建会重新计算所有向量，原文件和关联不受影响。继续吗？',
        total:'有效文件', ready:'已索引', available:'已发布可用', awaitingReview:'待审核', pending:'待索引', failed:'索引失败', disabled:'已停用', missing:'源文件缺失',
        idle:'空闲', scanning:'扫描文件', indexing:'生成向量', error:'失败', unreviewed:'待审核（不可用）', reviewed:'已通过（可用）', rejected:'已停用',
        skill:'技能', reference:'技能附件', poc:'PoC', allKinds:'技能与 PoC', allReviews:'全部发布状态',
        search:'搜索', queryHint:'描述需求，或输入 CVE、技能名称、产品关键词', cve:'精确 CVE', product:'产品元数据筛选',
        hint:'每 5 分钟扫描技能包和 PoC 变更。失败文件按 1、5、15、60 分钟退避；新增 PoC 放入 pocs_dir，不会自动下载或执行。',
        knowledgeNotice:'通用资料不再重复进入技能审核队列，可在知识管理中分类、编辑和向量检索。', goKnowledge:'打开知识管理',
        local:'向量在本机计算；原文件变化会重新索引并重置审核状态。', empty:'暂无匹配文件。可检查筛选或索引状态。',
        loading:'正在读取…', previous:'上一页', next:'下一页', details:'查看详情', source:'来源', state:'索引状态',
        hybrid:'混合检索', keyword:'关键词检索', candidates:'匹配候选（查询最多合并 120 条）', files:'文件', model:'向量模型',
        close:'关闭', sourceChanged:'原文件已变化或缺失；以下是索引快照。请先增量扫描，重新打开后再编辑。',
        raw:'查看完整原文快照', hash:'原文件 SHA-256', metadata:'元数据与人工审核', name:'标题', kind:'类型', review:'审核状态',
        reviewNote:'技能只有审核通过后才会进入 Agent 运行时；PoC 只有审核通过后才进入默认检索。通过不等于 PoC 已在目标上验证成功。',
        cves:'人工确认的 CVE（逗号分隔）', detected:'正文识别的 CVE（展示前 50 个，检索覆盖全部，仍需核验）', detectedCount:'识别总数', products:'产品（逗号分隔）',
        versions:'适用版本', prerequisites:'前置条件', license:'许可证', sourceURL:'来源链接', notes:'备注', save:'保存元数据',
        links:'对应技能与资料', package:'目录归属', manual:'手动关联', unlink:'删除关联', noLinks:'暂无关联。',
        linkSearch:'搜索待关联项', linkHint:'输入名称、CVE 或关键词；选中后才会建立关联', select:'请选择候选项', link:'添加关联', linkNote:'关联说明',
        saved:'已保存。需要重算的文件已进入索引队列。', queued:'已提交索引任务。', semantic:'语义匹配', skipped:'跳过文件',
        approve:'审核通过并发布', markUnreviewed:'撤回为待审核', disable:'停用', approvePage:'通过并发布本页待审核',
        reviewSaved:'审核状态已保存。', reviewPartial:'部分审核状态保存失败，请刷新后重试。', noPendingOnPage:'本页没有待审核记录。',
    };
    const escape = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    function t(key) { const value=typeof window!=='undefined'&&typeof window.t==='function'?window.t('skillLibrary.'+key):''; return value&&value!=='skillLibrary.'+key?value:(words[key]||key); }
    const tag = (code, allowed) => allowed.includes(code) ? code : allowed[0];
    const split = value => String(value||'').split(/[,，\n]+/).map(v=>v.trim()).filter(Boolean);
    function params(state) {const p=new URLSearchParams({page:String(state.page||1)});for(const key of ['q','kind','review','cve','product'])if(state[key])p.set(key,state[key]);return p.toString();}
    function reviewActions(d, allowReview=false) {
        if(!allowReview||d.missing)return '';
        const review=tag(d.review,['unreviewed','reviewed','rejected']);
        const actions=[];
        if(review==='unreviewed')actions.push(`<button class="btn-primary sl-review-btn" data-sl-review-id="${escape(d.id)}" data-sl-review="reviewed">${escape(t('approve'))}</button>`);
        else actions.push(`<button class="btn-secondary sl-review-btn" data-sl-review-id="${escape(d.id)}" data-sl-review="unreviewed">${escape(t('markUnreviewed'))}</button>`);
        if(review!=='rejected')actions.push(`<button class="btn-secondary sl-review-btn" data-sl-review-id="${escape(d.id)}" data-sl-review="rejected">${escape(t('disable'))}</button>`);
        return `<div class="sl-review-actions" aria-label="${escape(t('review'))}">${actions.join('')}</div>`;
    }
    function card(d, allowReview=false) {
        const kind=tag(d.kind,['reference','skill','poc']), review=tag(d.review,['unreviewed','reviewed','rejected']);
        const ids=[...new Set([...(d.metadata?.cves||[]),...(d.metadata?.detected_cves||[])])];
        return `<article class="sl-card"><div class="sl-card-head"><button class="sl-title" data-sl-open="${escape(d.id)}">${escape(d.title)}</button><span class="sl-tag">${escape(t(kind))}</span><span class="sl-tag sl-${review}">${escape(t(review))}</span></div>
            <p class="sl-path">${escape(d.root)} / ${escape(d.path)}</p><p class="sl-snippet">${escape(d.snippet||'')}</p>
            <div class="sl-tags">${ids.slice(0,6).map(id=>`<span class="sl-tag">${escape(id)}</span>`).join('')}${(d.matches||[]).map(m=>`<span class="sl-tag">${escape(t(m))}</span>`).join('')}
            <span class="sl-tag">${escape(t('state'))}: ${escape(t(d.state))}</span></div>${d.error?`<p class="sl-error">${escape(d.error)}</p>`:''}${reviewActions(d,allowReview)}</article>`;
    }
    function linksHTML(links, canWrite) {
        return links.map(l=>`<li><button class="sl-title" data-sl-open="${escape(l.skill_id)}">${escape(l.skill_title)}</button> → <button class="sl-title" data-sl-open="${escape(l.resource_id)}">${escape(l.resource_title)}</button>
            <span class="sl-tag">${escape(t(l.source==='package'?'package':'manual'))}</span><p>${escape(l.note)}</p>
            ${canWrite&&l.source==='manual'?`<button class="btn-secondary" data-sl-unlink="${escape(l.skill_id)}" data-resource="${escape(l.resource_id)}">${escape(t('unlink'))}</button>`:''}</li>`).join('')||`<li>${escape(t('noLinks'))}</li>`;
    }
    let root, timer, controller, seq=0, detailSeq=0, current, detailResult, candidateSeq=0, wasRunning=false, visibleDocuments=new Map();
    let state={page:1,q:'',kind:'skill',review:'reviewed',cve:'',product:''};
    const el=id=>document.getElementById('sl-'+id);
    const active=()=>root?.classList.contains('active');
    const canWrite=()=>typeof hasPermission==='function'&&hasPermission('skills:write');
    async function request(path,options={}) {const response=await apiFetch('/api/skill-library'+path,options);const data=await response.json();if(!response.ok)throw new Error(data.error||('HTTP '+response.status));return data;}
    function message(text,error=false) {el('message').textContent=text||'';el('message').className=error?'sl-error':'sl-hint';}
    function options(values) {return values.map(v=>`<option value="${v}">${escape(t(v))}</option>`).join('');}
    function layout() {
        root.innerHTML=`<div class="page-header"><div><h2>${escape(t('title'))}</h2><p>${escape(t('subtitle'))}</p></div><div class="sl-actions"><button id="sl-refresh" class="btn-secondary">${escape(t('refresh'))}</button>
            ${canWrite()?`<button id="sl-index" class="btn-primary">${escape(t('index'))}</button><button id="sl-rebuild" class="btn-secondary">${escape(t('rebuild'))}</button>`:''}</div></div><div class="page-content sl-page-content">
            <p class="sl-review-gate">${escape(t('reviewNote'))}</p><p class="sl-hint">${escape(t('knowledgeNotice'))} <button type="button" class="btn-secondary" id="sl-open-knowledge">${escape(t('goKnowledge'))}</button></p><p class="sl-hint">${escape(t('hint'))}</p><div id="sl-status" aria-live="polite"></div><p id="sl-message" role="status"></p>
            <form id="sl-search" class="sl-filters"><input id="sl-q" maxlength="500" placeholder="${escape(t('queryHint'))}" aria-label="${escape(t('search'))}"><select id="sl-kind" aria-label="${escape(t('kind'))}">${options(['skill','poc'])}</select>
            <select id="sl-review" aria-label="${escape(t('review'))}">${options(['reviewed','unreviewed','rejected'])}<option value="all">${escape(t('allReviews'))}</option></select>
            <input id="sl-cve" maxlength="30" placeholder="${escape(t('cve'))}" aria-label="${escape(t('cve'))}"><input id="sl-product" maxlength="66" placeholder="${escape(t('product'))}" aria-label="${escape(t('product'))}"><button class="btn-primary">${escape(t('search'))}</button></form>
            <p id="sl-count" class="sl-hint"></p><div class="sl-page-review"><button id="sl-review-page" class="btn-primary" hidden>${escape(t('approvePage'))}</button></div><section id="sl-results" aria-live="polite"></section><div class="sl-pagination"><button id="sl-prev" class="btn-secondary">${escape(t('previous'))}</button><span id="sl-page"></span><button id="sl-next" class="btn-secondary">${escape(t('next'))}</button></div>
            <dialog id="sl-dialog" aria-labelledby="sl-detail-title"><div class="sl-dialog-shell"><header><h2 id="sl-detail-title"></h2><button id="sl-close" class="btn-secondary">${escape(t('close'))}</button></header><div id="sl-detail" class="sl-dialog-body"></div><p id="sl-detail-error" class="sl-error" role="alert"></p></div></dialog></div>`;
        el('search').addEventListener('submit',ev=>{ev.preventDefault();state={page:1,...Object.fromEntries(['q','kind','review','cve','product'].map(k=>[k,el(k).value.trim()]))};refresh();});
        el('refresh').addEventListener('click',()=>{refresh();status();});
        el('open-knowledge').addEventListener('click',()=>{if(typeof switchPage==='function')switchPage('knowledge-management');});
        el('review-page')?.addEventListener('click',reviewCurrentPage);
        el('index')?.addEventListener('click',()=>startIndex(false));el('rebuild')?.addEventListener('click',()=>{if(window.confirm(t('rebuildConfirm')))startIndex(true);});
        el('prev').addEventListener('click',()=>{if(state.page>1){state.page--;refresh();}});el('next').addEventListener('click',()=>{state.page++;refresh();});
        el('close').addEventListener('click',()=>el('dialog').close());el('dialog').addEventListener('close',()=>{detailSeq++;candidateSeq++;current=null;});
        root.addEventListener('click',ev=>{const review=ev.target.closest('[data-sl-review]');if(review){changeReview(review.dataset.slReviewId,review.dataset.slReview,review);return}const open=ev.target.closest('[data-sl-open]');if(open){show(open.dataset.slOpen);return}const unlink=ev.target.closest('[data-sl-unlink]');if(unlink)changeLink({skill_id:unlink.dataset.slUnlink,resource_id:unlink.dataset.resource},true);});
    }
    async function refresh() {
        const mine=++seq;controller?.abort();controller=new AbortController();el('results').textContent=t('loading');
        try {const result=await request('/search?'+params(state),{signal:controller.signal});if(mine!==seq||!active())return;
            visibleDocuments=new Map(result.items.map(d=>[d.id,d]));
            el('results').innerHTML=result.items.map(d=>card(d,canWrite())).join('')||`<p class="sl-empty">${escape(t('empty'))}</p>`;
            const pendingOnPage=result.items.filter(d=>d.review==='unreviewed'&&!d.missing).length,reviewPage=el('review-page');if(reviewPage){reviewPage.hidden=!canWrite()||pendingOnPage===0;reviewPage.disabled=false;}
            el('count').textContent=t(result.mode)+' · '+result.total+' '+t(state.q?'candidates':'files');el('page').textContent=String(state.page);el('prev').disabled=state.page<=1;el('next').disabled=state.page*25>=result.total;
            message(result.warning||'');
        } catch(error){if(error.name!=='AbortError'&&mine===seq){el('results').textContent='';message(error.message,true);}}
    }
    async function status() {
        try {const data=await request('/status');if(!active())return;
            const stats=[['total',data.total],['available',data.available],['awaitingReview',data.awaiting_review],['pending',data.pending],['failed',data.failed],['disabled',data.disabled]];
            el('status').innerHTML=`<div class="sl-stats">${stats.map(([k,value])=>`<div><span>${escape(t(k))}</span><strong>${escape(value)}</strong></div>`).join('')}</div><p class="sl-hint">${escape(t(data.phase))} · ${escape(t('model'))}: ${escape(data.model)} / ${escape(data.dimension)} · ${escape(t('skipped'))}: ${escape(data.skipped)} · ${escape(t('local'))}</p>${data.last_error?`<p class="sl-error">${escape(data.last_error)}</p>`:''}`;
            if(el('index'))el('index').disabled=data.running;if(el('rebuild'))el('rebuild').disabled=data.running;
            if(wasRunning&&!data.running)refresh();wasRunning=data.running;
        }catch(error){if(active())message(error.message,true);}
    }
    async function startIndex(full) {try{await request('/index',{method:'POST',body:JSON.stringify({full})});message(t('queued'));status();}catch(error){message(error.message,true);}}
    function reviewBody(d,review) {return {title:d.title,kind:d.kind,review,revision:d.revision,metadata:d.metadata||{}};}
    async function saveReview(d,review) {return request('/documents/'+encodeURIComponent(d.id),{method:'PUT',body:JSON.stringify(reviewBody(d,review))});}
    async function changeReview(id,review,button) {
        const d=visibleDocuments.get(id);if(!d||!canWrite()||button?.disabled)return;if(button)button.disabled=true;
        try{await saveReview(d,review);await refresh();message(t('reviewSaved'));status();}
        catch(error){message(error.message,true);if(button?.isConnected)button.disabled=false;}
    }
    async function reviewCurrentPage() {
        const button=el('review-page'),docs=[...visibleDocuments.values()].filter(d=>d.review==='unreviewed'&&!d.missing);if(!docs.length){message(t('noPendingOnPage'));return;}button.disabled=true;
        const results=await Promise.allSettled(docs.map(d=>saveReview(d,'reviewed')));const failed=results.filter(r=>r.status==='rejected');await refresh();message(failed.length?t('reviewPartial'):t('reviewSaved'),failed.length>0);status();
    }
    function field(key,value,multiline=false) {return `<label>${escape(t(key))}${multiline?`<textarea id="sl-edit-${key}" maxlength="1800">${escape(value||'')}</textarea>`:`<input id="sl-edit-${key}" maxlength="${key==='sourceURL'?2000:300}" value="${escape(value||'')}">`}</label>`;}
    function detailHTML(result) {
        const d=result.document,m=d.metadata||{},write=canWrite()&&result.source_current&&!d.missing;
        return `${!result.source_current?`<p class="sl-error">${escape(t('sourceChanged'))}</p>`:''}<p class="sl-path">${escape(d.root)} / ${escape(d.path)}</p><p class="sl-path">${escape(t('hash'))}: ${escape(d.hash)}</p>
            <p>${escape(t('detectedCount'))}: ${escape(d.detected_cve_count??(m.detected_cves||[]).length)}</p><p>${escape(t('detected'))}: ${escape((m.detected_cves||[]).join(', ')||'—')}</p><details><summary>${escape(t('raw'))}</summary><pre>${escape(d.content)}</pre></details>
            <h3>${escape(t('metadata'))}</h3><p class="sl-hint">${escape(t('reviewNote'))}</p><form id="sl-edit"><fieldset ${write?'':'disabled'}>
            ${field('name',d.title)}<label>${escape(t('kind'))}<select id="sl-edit-kind" ${d.kind==='skill'?'disabled':''}>${options(d.kind==='skill'?['skill']:['reference','poc'])}</select></label>
            <label>${escape(t('review'))}<select id="sl-edit-review">${options(['unreviewed','reviewed','rejected'])}</select></label>${field('cves',(m.cves||[]).join(', '))}${field('products',(m.products||[]).join(', '))}
            ${field('versions',m.versions,true)}${field('prerequisites',m.prerequisites,true)}${field('license',m.license)}${field('sourceURL',m.source_url)}${field('notes',m.notes,true)}
            ${write?`<button id="sl-save" class="btn-primary">${escape(t('save'))}</button>`:''}</fieldset></form><h3>${escape(t('links'))}</h3><ul class="sl-links">${linksHTML(result.links,canWrite())}</ul>
            ${write?`<form id="sl-link-search" class="sl-filters"><input id="sl-link-query" maxlength="500" placeholder="${escape(t('linkHint'))}" aria-label="${escape(t('linkSearch'))}"><button class="btn-secondary">${escape(t('linkSearch'))}</button></form>
            <form id="sl-link-form" class="sl-filters"><select id="sl-link-target" required aria-label="${escape(t('select'))}"><option value="">${escape(t('select'))}</option></select><input id="sl-link-note" maxlength="600" placeholder="${escape(t('linkNote'))}" aria-label="${escape(t('linkNote'))}"><button id="sl-link-save" class="btn-secondary">${escape(t('link'))}</button></form>`:''}`;
    }
    async function show(id) {
        const mine=++detailSeq;candidateSeq++;current=id;el('detail-title').textContent=t('loading');el('detail').textContent='';el('detail-error').textContent='';if(!el('dialog').open)el('dialog').showModal();
        try{const result=await request('/documents/'+encodeURIComponent(id));if(mine!==detailSeq||!el('dialog').open)return;detailResult=result;el('detail-title').textContent=result.document.title;el('detail').innerHTML=detailHTML(result);
            el('edit-kind').value=result.document.kind;el('edit-review').value=result.document.review;
            el('edit').addEventListener('submit',saveMetadata);el('link-search')?.addEventListener('submit',searchLinks);el('link-form')?.addEventListener('submit',ev=>{ev.preventDefault();const selected=el('link-target').value;if(!selected)return;const skill=detailResult.document.kind==='skill';changeLink({skill_id:skill?current:selected,resource_id:skill?selected:current,note:el('link-note').value},false);});
        }catch(error){if(mine===detailSeq)el('detail-error').textContent=error.message;}
    }
    async function saveMetadata(ev) {
        ev.preventDefault();const mine=detailSeq,id=current,d=detailResult.document;const button=el('save');if(!button||button.disabled)return;button.disabled=true;
        const value=key=>el('edit-'+key).value;
        const body={title:value('name'),kind:value('kind'),review:value('review'),revision:d.revision,metadata:{cves:split(value('cves')),products:split(value('products')),versions:value('versions'),prerequisites:value('prerequisites'),license:value('license'),source_url:value('sourceURL'),notes:value('notes')}};
        try{await request('/documents/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify(body)});if(mine===detailSeq&&el('dialog').open){await show(id);message(t('saved'));refresh();status();}}
        catch(error){if(mine===detailSeq)el('detail-error').textContent=error.message;}finally{if(button.isConnected)button.disabled=false;}
    }
    async function searchLinks(ev) {
        ev.preventDefault();const mine=++candidateSeq,detail=detailSeq,skill=detailResult.document.kind==='skill';const q=el('link-query').value.trim();
        try{const result=await request('/search?'+params({q,kind:skill?'':'skill',page:1}));if(mine!==candidateSeq||detail!==detailSeq)return;
            const items=result.items.filter(d=>d.id!==current&&(skill?d.kind!=='skill':d.kind==='skill'));
            el('link-target').innerHTML=`<option value="">${escape(t('select'))}</option>`+items.map(d=>`<option value="${escape(d.id)}">${escape(d.title)} · ${escape(d.path)}</option>`).join('');
        }catch(error){if(detail===detailSeq)el('detail-error').textContent=error.message;}
    }
    async function changeLink(body,remove) {
        const mine=detailSeq,id=current;const button=el('link-save');if(button)button.disabled=true;
        try{await request('/links',{method:remove?'DELETE':'POST',body:JSON.stringify(body)});if(mine===detailSeq&&el('dialog').open)await show(id);}catch(error){if(mine===detailSeq)el('detail-error').textContent=error.message;}finally{if(button?.isConnected)button.disabled=false;}
    }
    function init() {root=document.getElementById('page-skill-library');if(!root)return;if(!el('results'))layout();refresh();status();if(!timer)timer=setInterval(()=>{if(active())status();},5000);}
    return {init,escape,params,card,reviewActions,reviewBody,linksHTML,detailHTML,split,words};
})();
if(typeof window!=='undefined')window.initSkillLibrary=()=>SkillLibrary.init();
if(typeof module!=='undefined')module.exports=SkillLibrary;
