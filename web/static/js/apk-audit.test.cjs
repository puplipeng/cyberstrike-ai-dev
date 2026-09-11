const test=require('node:test');
const assert=require('node:assert/strict');
const report=require('./apk-audit.js');
const record={name:'example.apk',sha256:'abc',result:{source:'SINGLE CLASS SHOULD NOT WIN'},audit_report:{
    run_id:'run',rule_version:'test',created:'now',coverage:{dex_parsed:1,dex_total:2,classes_audited:2,classes_total:4,methods_audited:4,methods_total:9,methods_without_code:1,methods_failed:2,methods_unprocessed:2,complete:false,report_complete:false,source_complete:false,findings_total:3,findings_omitted:2,source_omitted:1,errors_total:1},
    limitations:['partial only'],gaps:[{dex:'classes2.dex',class_name:'C',method:'f',reason:'parse error'}],rules:[],references:[],
    findings:[{title:'candidate',cwe:'CWE-89',severity:'high',id:'1',rule:'sql',dex:'classes.dex',class_name:'A',method:'f',line:3,evidence:'x\n```\n<img src=x>',conditions:'check reachability',recommendation:'bind parameters'}]
}};
test('export uses whole report, preserves gaps and pending status',()=>{
    const text=report.markdown(record);
    assert.match(text,/完整审计类：2\/4/);assert.match(text,/省略：2/);assert.match(text,/parse error/);assert.match(text,/均未验证/);
    assert.ok(!text.includes('SINGLE CLASS SHOULD NOT WIN'));assert.ok(text.includes('    ```'));
});
test('AI draft includes non-hit methods and explicit remaining batches',()=>{
    const text=report.draft(record,{offset:0,next_offset:2,has_more:true,chunks:[{dex:'classes.dex',class_name:'B',method:'g',source:'unmatched source'},{dex:'classes.dex',class_name:'A',method:'f',source:'candidate source'}]});
    assert.match(text,/unmatched source/);assert.match(text,/candidate source/);assert.match(text,/"has_more": true/);
    assert.match(text,/不把草稿生成/);assert.match(text,/check reachability/);assert.ok(!text.includes('SINGLE CLASS SHOULD NOT WIN'));
});
test('no-hit report never implies code is safe',()=>{
    const copy=structuredClone(record);copy.audit_report.findings=[];
    assert.match(report.markdown(copy),/不代表不存在漏洞/);
});
