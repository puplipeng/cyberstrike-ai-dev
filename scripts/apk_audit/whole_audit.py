"""Walk every DEX/class/method; retain bounded source batches for subsequent AI review."""
import datetime, gc, hashlib, json, pathlib, re, time
from rules import analyze_method, RULES, VERSION, REFERENCES

LIMITATIONS = [
    '整包指遍历所有受支持的 DEX 类与方法，并不代表发现全部漏洞。',
    '反编译为近似 Java；规则仅做方法内词法传播，不证明跨方法、跨组件可达性或漏洞可利用性。',
    'JNI/原生库、动态下载代码、服务端逻辑、运行时行为及资源中的脚本不在本次代码规则覆盖范围。',
    '未命中不等于安全；解析失败、时间/存储限制及报告截断均列入覆盖说明。',
    'AI 草稿按源码批次生成，需逐批审阅；未发送的批次不算 AI 已审计。',
]

def audit(dexes, manifest, req, root, class_names, manifest_xml):
    xml, xml_kind = manifest_xml(manifest)
    dumps = json.dumps
    # Import ASC only after the caller established process and network limits.
    import sys
    sys.path.insert(0, str(pathlib.Path(root).resolve()))
    from src.asc_client.asc_handler import _lazy_import
    _lazy_import()
    from src.asc_core.utils.decompiler import DEX, FakeAnalysis, decompile
    from loguru import logger
    logger.remove()
    run_id = req.get('run_id', '')
    if not re.fullmatch('[a-f0-9]{32}', run_id): raise ValueError('Invalid audit run ID')
    started = time.monotonic()
    budget = max(0.01, min(1500, float(req.get('budget_seconds', 1500))))
    path = pathlib.Path(req['apk']).resolve().parent / ('audit-source-' + run_id + '.jsonl')
    inventory = [(name, data, class_names(data)) for name, data in dexes]
    coverage = dict(dex_total=len(dexes), dex_parsed=0, classes_total=sum(len(x[2]) for x in inventory),
                    classes_visited=0, classes_audited=0, methods_total=0, methods_audited=0,
                    methods_failed=0, methods_without_code=0, source_chunks=0, source_bytes=0,
                    source_omitted=0, findings_total=0, findings_omitted=0, errors_total=0)
    report = dict(mode='audit_apk', run_id=run_id, rule_version=VERSION,
                  created=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  scope='all_supported_dex_classes_and_methods', coverage=coverage, findings=[], gaps=[],
                  limitations=LIMITATIONS, rules=[dict(id=k,title=v[0],severity=v[1],cwe=v[2]) for k,v in RULES.items()], references=REFERENCES)
    report['manifest'], report['manifest_kind'] = xml, xml_kind
    report['manifest'] = report['manifest'][:65536]
    finding_bytes = 0
    expired = False
    def gap(dex, clz, method, reason):
        coverage['errors_total'] += 1
        if len(report['gaps']) < 100:
            report['gaps'].append(dict(dex=dex, class_name=clz, method=method, reason=str(reason)[:300]))
    with path.open('x', encoding='utf-8', newline='\n') as output:
        def retain(source, dex_name, name, signature, context):
            for offset in range(0, len(source), 16000):
                chunk = dict(dex=dex_name, class_name=name, method=signature, context=context,
                             start_line=source.count('\n',0,offset)+1, continued=offset>0,
                             source=source[offset:offset+16000])
                line = dumps(chunk, ensure_ascii=False)+'\n'
                size = len(line.encode('utf-8'))
                if coverage['source_bytes']+size > 64*1024*1024:
                    coverage['source_omitted'] += 1; continue
                output.write(line)
                coverage['source_bytes'] += size
                coverage['source_chunks'] += 1
        for dex_name, data, names in inventory:
            if time.monotonic()-started > budget: expired = True; break
            try:
                vm = DEX(data)
                coverage['dex_parsed'] += 1
                coverage['methods_total'] += sum(len(c.get_methods()) for c in vm.get_classes())
            except Exception as e:
                gap(dex_name, '', '', e); continue
            for clz in vm.get_classes():
                if time.monotonic()-started > budget: expired = True; break
                name = clz.get_name()
                coverage['classes_visited'] += 1
                try:
                    # One analysis cache per class: do not retain graphs for the entire APK.
                    dv = decompile.DvClass(clz, FakeAnalysis(vm))
                    context = name + ' extends ' + str(clz.get_superclassname()) + ' implements ' + str(clz.get_interfaces())
                    # Before methods are processed get_source contains class/field declarations only.
                    retain(dv.get_source(), dex_name, name, '<class declarations>', context)
                    class_ok = True
                    for i, encoded in enumerate(list(clz.get_methods())):
                        if time.monotonic()-started > budget: expired = True; class_ok = False; break
                        method = encoded.get_name()
                        signature = method + encoded.get_descriptor()
                        if not encoded.get_code():
                            coverage['methods_without_code'] += 1
                            retain('// No DEX method body: '+signature, dex_name, name, signature, context)
                            continue
                        try:
                            # DvClass.process() hides per-method failures. Call individually instead.
                            dv.process_method(i)
                            source = dv.methods[i].get_source()
                            if not source.strip(): raise ValueError('No method source returned')
                            if len(source.encode('utf-8')) > 2*1024*1024: raise ValueError('Method source exceeds 2 MiB rule budget')
                            hits = analyze_method(source, method, context)
                            coverage['methods_audited'] += 1
                            for f in hits:
                                coverage['findings_total'] += 1
                                f.update(dex=dex_name, class_name=name, method=signature)
                                f['id'] = hashlib.sha256((dex_name+name+signature+f['rule']+str(f['line'])).encode()).hexdigest()[:16]
                                size = len(dumps(f, ensure_ascii=False).encode('utf-8'))
                                if finding_bytes+size <= 1800000 and len(report['findings']) < 1000:
                                    report['findings'].append(f); finding_bytes += size
                                else: coverage['findings_omitted'] += 1
                            # Source batches cover methods without rule hits too; never only selected classes.
                            retain(source, dex_name, name, signature, context)
                        except Exception as e:
                            class_ok = False; coverage['methods_failed'] += 1
                            gap(dex_name, name, signature, e)
                    if class_ok: coverage['classes_audited'] += 1
                    del dv
                except Exception as e:
                    gap(dex_name, name, '', e)
                if expired: break
            del vm
            gc.collect()
            if expired: break
    coverage['classes_not_fully_audited'] = coverage['classes_total']-coverage['classes_audited']
    coverage['methods_unprocessed'] = max(0, coverage['methods_total']-coverage['methods_audited']-coverage['methods_failed']-coverage['methods_without_code'])
    coverage['time_budget_exceeded'] = expired
    coverage['elapsed_seconds'] = round(time.monotonic()-started, 2)
    coverage['complete'] = not expired and coverage['classes_not_fully_audited']==0 and coverage['errors_total']==0
    coverage['report_complete'] = coverage['findings_omitted']==0
    coverage['source_complete'] = coverage['source_omitted']==0 and coverage['complete']
    report['findings'].sort(key=lambda f: (f['severity'],f['dex'],f['class_name'],f['method'],f['line']))
    report['note'] = '整包静态规则审核完成；所有命中均待研判。' if coverage['complete'] else '仅部分代码完成规则审核，请查看覆盖缺口。'
    return report
