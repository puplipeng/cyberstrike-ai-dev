"""Tiny synthetic DEX: HostnameVerifier.verify returns true. No networking/code execution."""
import hashlib, struct, zlib

def fixture():
    def ul(n):
        b=bytearray()
        while n>127: b.append((n&127)|128); n>>=7
        return bytes(b)+bytes([n])
    types=['Laudit/Vulnerable;','Ljava/lang/Object;','Ljava/lang/String;','Ljavax/net/ssl/HostnameVerifier;','Ljavax/net/ssl/SSLSession;','Z']
    strings=sorted(types+['ZLL','verify']); ids={s:i for i,s in enumerate(strings)}
    si=112; ti=si+4*len(strings); pi=ti+4*len(types); mi=pi+12; ci=mi+8; dataoff=ci+32
    buf=bytearray(dataoff); stringoff=[]
    for s in strings: stringoff.append(len(buf)); buf.extend(ul(len(s))+s.encode()+b'\0')
    def align():
        while len(buf)%4:buf.append(0)
    align(); interfaces=len(buf); buf.extend(struct.pack('<IH',1,3)); align()
    params=len(buf); buf.extend(struct.pack('<IHH',2,2,4)); align()
    codeoff=len(buf); buf.extend(struct.pack('<HHHHIIHH',4,3,0,0,0,2,0x1012,0x000f))
    classoff=len(buf); buf.extend(b'\0\0\0\1'+ul(0)+ul(1)+ul(codeoff)); align()
    mapoff=len(buf)
    entries=[(0,1,0),(1,len(strings),si),(2,len(types),ti),(3,1,pi),(5,1,mi),(6,1,ci),(0x2002,len(strings),stringoff[0]),(0x1001,2,interfaces),(0x2001,1,codeoff),(0x2000,1,classoff),(0x1000,1,mapoff)]
    buf.extend(struct.pack('<I',len(entries)))
    for kind,n,off in entries:buf.extend(struct.pack('<HHII',kind,0,n,off))
    for i,off in enumerate(stringoff):struct.pack_into('<I',buf,si+4*i,off)
    for i,t in enumerate(types):struct.pack_into('<I',buf,ti+4*i,ids[t])
    struct.pack_into('<III',buf,pi,ids['ZLL'],5,params)
    struct.pack_into('<HHI',buf,mi,0,0,ids['verify'])
    struct.pack_into('<8I',buf,ci,0,1,1,interfaces,0xffffffff,0,classoff,0)
    buf[:8]=b'dex\n035\0'
    struct.pack_into('<20I',buf,32,len(buf),112,0x12345678,0,0,mapoff,len(strings),si,len(types),ti,1,pi,0,0,1,mi,1,ci,len(buf)-dataoff,dataoff)
    buf[12:32]=hashlib.sha1(buf[32:]).digest(); struct.pack_into('<I',buf,8,zlib.adler32(buf[12:])&0xffffffff)
    return bytes(buf)
