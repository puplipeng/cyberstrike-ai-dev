import importlib.util, pathlib, unittest, tempfile, zipfile, struct, hashlib, zlib, sys, os, subprocess, json, uuid
BASE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(BASE))
from rules import analyze_method
spec=importlib.util.spec_from_file_location('apk_worker',pathlib.Path(__file__).with_name('worker.py'));worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
class GuardTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
 def apk(self,entries):
  p=pathlib.Path(self.tmp.name)/'sample.apk'
  with zipfile.ZipFile(p,'w',zipfile.ZIP_DEFLATED) as z:
   for name,data in entries:z.writestr(name,data)
  return p
 def test_invalid_archives(self):
  for entries in [[('../evil',b'x')],[('x',b'a'*1000000)],[('x',b'1'),('x',b'2')],[('classes.dex',b'bad'),('AndroidManifest.xml',b'x')]]:
   with self.subTest(entries=[n for n,_ in entries]):
    with self.assertRaises(ValueError):worker.load_apk(self.apk(entries))
 def test_checksum_and_range(self):
  sample=(BASE/'testdata/sample.dex').read_bytes();self.assertEqual(worker.checked_dex(sample),sample)
  b=bytearray(sample);b[-1]^=1
  with self.assertRaises(ValueError):worker.checked_dex(b)
  b=bytearray(sample);struct.pack_into('<I',b,60,0xffffffff);b[12:32]=hashlib.sha1(b[32:]).digest();struct.pack_into('<I',b,8,zlib.adler32(b[12:])&0xffffffff)
  with self.assertRaises(ValueError):worker.checked_dex(b)
 def test_xml_entities(self):
  with self.assertRaises(ValueError):worker.manifest_xml(b'<!DOCTYPE foo [<!ENTITY e SYSTEM "file:///secret">]><foo>&e;</foo>')
 def test_audit_candidate_only(self):
  for source in ['return "safe";', 'catch (RuntimeException e) { throw e; }','Runtime.getRuntime().exec(command);','handler.proceed();','db.rawQuery(query, null);']:
   self.assertEqual(analyze_method(source),[])
  hits=analyze_method('String x=getIntent().getStringExtra("cmd");\nRuntime.getRuntime().exec(x);')
  self.assertEqual([x['rule'] for x in hits],['command-input'])
  self.assertTrue(all(x['status']=='needs_review' for x in hits))
  self.assertEqual(hits[0]['line'],2)
 def test_rules_positive_and_negative(self):
  cases=[
   ('sql-input','String x=getIntent().getStringExtra("q"); db.rawQuery("select * where x="+x,null);'),
   ('webview-script-input','String x=getQueryParameter("js"); web.evaluateJavascript(x,null);'),
   ('dynamic-input','String x=getIntent().getStringExtra("path"); new DexClassLoader(x,tmp,null,parent);'),
   ('file-input','String x=getIntent().getStringExtra("path"); File f=new File(root,x); new FileOutputStream(f);'),
  ]
  for rule,code in cases:
   with self.subTest(rule=rule):self.assertIn(rule,[f['rule'] for f in analyze_method(code)])
  for code in [
   'String x=getStringExtra("q"); db.rawQuery("select * where x=?",new String[]{x});',
   'String x=getStringExtra("q"); x="fixed"; Runtime.getRuntime().exec(x);',
   '// Runtime.getRuntime().exec(getStringExtra("cmd"));',
   'String text="Runtime.getRuntime().exec(getIntent())";',
   '/* db.rawQuery(getQueryParameter("q"),null); */',
   'new DexClassLoader("/private/verified.dex",tmp,null,parent);',
  ]:
   with self.subTest(code=code):self.assertEqual(analyze_method(code),[])
 def test_tls_context(self):
  self.assertEqual(len(analyze_method('public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }','onReceivedSslError')),1)
  self.assertEqual(analyze_method('public void proceed(){task.proceed();}','proceed'),[])
  self.assertEqual(len(analyze_method('public void checkServerTrusted(X509Certificate[] c,String a) { return; }','checkServerTrusted','implements javax.net.ssl.X509TrustManager')),1)
  self.assertEqual(analyze_method('public void checkServerTrusted(X509Certificate[] c,String a) { throw new CertificateException(); }','checkServerTrusted','X509TrustManager'),[])
  self.assertEqual(len(analyze_method('public boolean verify(String h,SSLSession s){return true;}','verify','HostnameVerifier')),1)
  self.assertEqual(analyze_method('public boolean verify(String h,SSLSession s){return false;}','verify','HostnameVerifier'),[])
 def test_network_guard(self):
  for event in ['socket.connect','socket.getaddrinfo','subprocess.Popen','os.system']:
   with self.assertRaises(PermissionError):worker.deny_network(event,())
 def test_lock_rejects_changes(self):
  with self.assertRaises(ValueError):worker.verify_engine(self.tmp.name)
 @unittest.skipUnless(os.environ.get('APK_TEST_BASE'),'requires pinned ASC engine')
 def test_whole_multidex_positive_and_deadline(self):
  from testdata.make_hostname_fixture import fixture
  base=pathlib.Path(os.environ['APK_TEST_BASE'])
  apk=self.apk([('classes.dex',(BASE/'testdata/sample.dex').read_bytes()),('classes2.dex',fixture()),('AndroidManifest.xml',b'<manifest package="audit.fixture"/>')])
  def run(budget, target=None):
   req={'apk':str(target or apk),'mode':'audit_apk','run_id':uuid.uuid4().hex,'budget_seconds':budget}
   p=subprocess.run([str(base/'venv/Scripts/python.exe'),'-I','-X','utf8',str(BASE/'worker.py'),'--asc-root',str(base/'ASC')],input=json.dumps(req),capture_output=True,text=True,encoding='utf-8',timeout=30)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr)
   return json.loads(p.stdout)
  report=run(20)
  self.assertEqual(report['coverage']['dex_parsed'],2)
  self.assertEqual(report['coverage']['methods_audited'],2)
  self.assertTrue(report['coverage']['complete'])
  self.assertEqual([f['rule'] for f in report['findings']],['hostname-all'])
  self.assertEqual(report['findings'][0]['dex'],'classes2.dex')
  self.assertEqual(report['findings'][0]['status'],'needs_review')
  source=(apk.parent/('audit-source-'+report['run_id']+'.jsonl')).read_text(encoding='utf-8')
  self.assertIn('audit-marker',source); self.assertIn('verify',source)
  real=base/'fixtures/TestActivity.apk'
  if real.exists():
   local=pathlib.Path(self.tmp.name)/'deadline.apk';local.write_bytes(real.read_bytes())
   partial=run(.01,local)
   self.assertFalse(partial['coverage']['complete'])
   self.assertTrue(partial['coverage']['time_budget_exceeded'])
   self.assertGreater(partial['coverage']['classes_not_fully_audited'],0)
if __name__=='__main__':unittest.main()
