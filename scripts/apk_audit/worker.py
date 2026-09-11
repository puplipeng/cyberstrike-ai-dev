"""Single-use, offline APK worker. Never installs or executes code from an APK."""
import argparse, hashlib, io, json, os, pathlib, re, struct, sys, zlib, zipfile
from xml.etree import ElementTree as ET
DUMPS = json.dumps
MAX_DEX = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_TEXT = 2 * 1024 * 1024

def deny_network(event, args):
    if event in ('socket.connect', 'socket.connect_ex', 'socket.bind', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'):
        raise PermissionError('Network and child process creation are disabled in APK workers')

def checked_dex(data):
    if len(data) < 112 or data[:8] not in [b'dex\n'+v+b'\0' for v in (b'035',b'037',b'038',b'039',b'040')]:
        raise ValueError('Unsupported or invalid DEX (supported: 035, 037-040)')
    if struct.unpack_from('<III',data,32) != (len(data),112,0x12345678): raise ValueError('Invalid DEX header')
    if struct.unpack_from('<I',data,8)[0] != zlib.adler32(data[12:]) & 0xffffffff: raise ValueError('Invalid DEX checksum')
    if data[12:32] != hashlib.sha1(data[32:]).digest(): raise ValueError('Invalid DEX signature')
    for pos,width in [(56,4),(64,4),(72,12),(80,8),(88,8),(96,32)]:
        n,off=struct.unpack_from('<II',data,pos)
        if n>1000000 or (n and (off<112 or off+n*width>len(data))):raise ValueError('DEX table outside file')
    return data

def load_apk(path):
    if pathlib.Path(path).stat().st_size>256*1024*1024:raise ValueError('APK exceeds 256 MiB')
    dexes=[];manifest=None;names=set();total=0
    with zipfile.ZipFile(path) as z:
        infos=z.infolist()
        if len(infos)>20000:raise ValueError('Too many archive entries')
        for x in infos:
            name=x.filename
            if name in names or '\\' in name or ':' in name or name.startswith('/') or '..' in name.split('/') or ((x.external_attr>>16)&0o170000)==0o120000:
                raise ValueError('Duplicate, unsafe or symlink archive entry')
            names.add(name);total+=x.file_size
            if x.flag_bits&1 or x.compress_type not in (0,8):raise ValueError('Encrypted or unsupported ZIP entry')
            if total>MAX_TOTAL or x.file_size>MAX_DEX or x.file_size>max(1,x.compress_size)*200:raise ValueError('Archive expansion budget exceeded')
            if re.fullmatch(r'classes(?:[2-9][0-9]*|1[0-9]+)?\.dex',name):
                if len(dexes)>=64:raise ValueError('Too many DEX files')
                with z.open(x) as f:data=f.read(MAX_DEX+1)
                if len(data)!=x.file_size:raise ValueError('DEX length mismatch')
                dexes.append((name,checked_dex(data)))
            elif name=='AndroidManifest.xml':
                if x.file_size>4*1024*1024:raise ValueError('Manifest too large')
                with z.open(x) as f:manifest=f.read(4*1024*1024+1)
        if not dexes:raise ValueError('No supported classes DEX in APK')
        if manifest is None:raise ValueError('AndroidManifest.xml missing')
    return dexes,manifest,len(names)

def manifest_xml(data):
    if data.lstrip().startswith(b'<'):
        if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError('XML entities are not accepted')
        ET.fromstring(data)
        return data.decode('utf-8'), 'plain_xml_fixture'
    from loguru import logger
    logger.remove()
    from androguard.core.axml import AXMLPrinter
    axml=AXMLPrinter(data)
    if not axml.is_valid():raise ValueError('Invalid binary Android manifest')
    return axml.get_xml().decode('utf-8'),'binary_axml'

def class_names(data):
    count,off=struct.unpack_from('<II',data,96);out=[]
    s_count,s_off=struct.unpack_from('<II',data,56);t_count,t_off=struct.unpack_from('<II',data,64)
    for i in range(count):
        t=struct.unpack_from('<I',data,off+i*32)[0]
        if t>=t_count:raise ValueError('Bad class index')
        s=struct.unpack_from('<I',data,t_off+t*4)[0]
        if s>=s_count:raise ValueError('Bad string index')
        at=struct.unpack_from('<I',data,s_off+s*4)[0]
        for _ in range(5):
            if at>=len(data):raise ValueError('Truncated string')
            b=data[at];at+=1
            if b<128:break
        else:raise ValueError('Malformed LEB128')
        end=data.find(b'\0',at,at+4096)
        if end<0:raise ValueError('Unterminated class name')
        out.append(data[at:end].decode('utf-8',errors='replace'))
    return out

def perform(req,root):
    dexes,manifest,entry_count=load_apk(req['apk'])
    mode=req.get('mode','inspect');query=req.get('query','')
    if mode=='audit_apk':
        sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
        from whole_audit import audit
        return audit(dexes,manifest,req,root,class_names,manifest_xml)
    if mode=='inspect':
        xml,kind=manifest_xml(manifest);items=[]
        for name,data in dexes:
            items.extend({'dex':name,'name':clz} for clz in class_names(data))
            if len(items)>50000:raise ValueError('Class list exceeds 50000 entries')
        return {'mode':mode,'classes':items,'dex_count':len(dexes),'entries':entry_count,'manifest':xml[:MAX_TEXT],'manifest_kind':kind,'note':'Static inventory only; APK is never installed or executed.'}
    if len(query)>256 or not query or any(ord(c)<32 for c in query):raise ValueError('Invalid query')
    if mode not in ('refs','decompile','disassemble'):raise ValueError('Unsupported operation; use audit_apk for whole-APK auditing')
    sys.path.insert(0,str(pathlib.Path(root).resolve()))
    if mode=='refs':
        from src.asc_client.asc_handler import AscHandler
        kind=req.get('kind','string')
        if kind not in ('string','type','method','field'):raise ValueError('Invalid reference kind')
        find={kind:query} if kind in ('string','type') else {kind:{'class':None,kind:query}}
        result=[]
        for name,data in dexes:
            result.extend(AscHandler().findrefs(name,data,kind,find,aggregate=False))
            if len(result)>2000:raise ValueError('More than 2000 hits; narrow the query')
        return {'mode':mode,'kind':kind,'query':query,'references':result}
    clz=query if query.startswith('L') and query.endswith(';') else 'L'+query.replace('.','/')+';'
    matches=[(name,data) for name,data in dexes if clz in class_names(data)]
    if len(matches)!=1:raise ValueError('Class absent or duplicated across DEX files')
    name,data=matches[0]
    if mode=='disassemble':
        from loguru import logger
        logger.remove()
        from androguard.core.dex import DEX
        c=DEX(data).get_class(clz);lines=[]
        for method in c.get_methods():
            lines.append(method.get_name()+method.get_descriptor())
            for off,ins in method.get_instructions_idx():
                lines.append(f'{off:08x}: {ins.get_name()} {ins.get_output()}')
        source='\n'.join(lines)
    else:
        from src.asc_client.asc_handler import _lazy_import
        _lazy_import()
        from src.asc_core.core.dex.dex_manager import DexManager
        from src.asc_core.utils.decompiler import decompile_dex_bytes
        rebuilt=bytearray(DexManager(memoryview(data)).extract_and_rebuild(clz))
        # ASC leaves integrity fields zero. Repair only the derived DEX, never input.
        rebuilt[12:32]=hashlib.sha1(rebuilt[32:]).digest()
        struct.pack_into('<I',rebuilt,8,zlib.adler32(rebuilt[12:])&0xffffffff)
        source=decompile_dex_bytes(rebuilt,clz)
        if not source.strip() or source.lstrip().startswith('Error:'):raise ValueError('ASC did not produce the requested class')
    if len(source.encode('utf-8'))>MAX_TEXT:raise ValueError('Source output limit exceeded')
    return {'mode':mode,'dex':name,'class':clz,'source':source,'findings':[],'note':'Decompiled source is approximate. Run audit_apk for whole-APK rule assessment.'}


def limit_resources():
    if os.name != 'nt':
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024,1024*1024*1024))
        return None
    import ctypes as C
    from ctypes import wintypes as W
    class Basic(C.Structure):
        _fields_=[('process_time',C.c_int64),('job_time',C.c_int64),('flags',W.DWORD),('min_ws',C.c_size_t),('max_ws',C.c_size_t),('active',W.DWORD),('affinity',C.c_size_t),('priority',W.DWORD),('scheduling',W.DWORD)]
    class IO(C.Structure):
        _fields_=[(n,C.c_uint64) for n in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    class Extended(C.Structure):
        _fields_=[('basic',Basic),('io',IO),('process_memory',C.c_size_t),('job_memory',C.c_size_t),('peak_process',C.c_size_t),('peak_job',C.c_size_t)]
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateJobObjectW.argtypes=[C.c_void_p,W.LPCWSTR];k.CreateJobObjectW.restype=W.HANDLE
    k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];k.SetInformationJobObject.restype=W.BOOL
    k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE];k.AssignProcessToJobObject.restype=W.BOOL
    k.GetCurrentProcess.restype=W.HANDLE
    job=k.CreateJobObjectW(None,None);limits=Extended();limits.basic.flags=0x100|0x8;limits.basic.active=1;limits.process_memory=1024*1024*1024
    if not job or not k.SetInformationJobObject(job,9,C.byref(limits),C.sizeof(limits)) or not k.AssignProcessToJobObject(job,k.GetCurrentProcess()):
        raise RuntimeError('Unable to establish worker resource limits')
    return job

def verify_engine(root):
    base=pathlib.Path(root).resolve()
    lock=json.loads(pathlib.Path(__file__).with_name('asc-lock.json').read_text(encoding='utf-8'))
    actual={str(p.relative_to(base)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in base.rglob('*.py') if '__pycache__' not in p.parts and '.git' not in p.parts}
    if actual!=lock['files']:raise ValueError('ASC source changed since review; refusing execution')
    from importlib.metadata import version
    if version('androguard')!='4.1.4' or version('mutf8')!='1.1.0':raise ValueError('Unexpected engine dependency version')

def main():
    p=argparse.ArgumentParser();p.add_argument('--asc-root',required=True);args=p.parse_args()
    req=json.loads(sys.stdin.buffer.read(4096))
    sys.addaudithook(deny_network)
    output=sys.stdout
    # ASC patches sys.modules globally. This worker handles exactly one operation.
    try:
        resource_handle=limit_resources()
        verify_engine(args.asc_root)
        with open(os.devnull,'w') as sink:
            sys.stdout=sink;result=perform(req,args.asc_root)
        text=DUMPS(result,ensure_ascii=False)
        if len(text.encode())>4*1024*1024:raise ValueError('Result exceeds 4 MiB')
        output.write(text)
    except Exception as e:
        output.write(DUMPS({'error':str(e)[:1000]},ensure_ascii=False));sys.exit(1)
if __name__=='__main__':main()
