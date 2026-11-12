import socket,ssl,struct,json,sys
import os; D=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,D); from parse import parse_hello
port=int(sys.argv[1]); out=sys.argv[2]
ls=socket.socket(); ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); ls.bind(('127.0.0.1',port)); ls.listen(1)
c,_=ls.accept(); c.settimeout(10)
buf=b''
while True:
    buf=c.recv(65536,socket.MSG_PEEK)
    p=0;done=False
    while p+5<=len(buf):
        l=struct.unpack('>H',buf[p+3:p+5])[0]
        if p+5+l>len(buf): break
        hs=buf[5:p+5+l]
        if len(hs)>=4 and len(hs)-4>=int.from_bytes(hs[1:4],'big'): done=True;break
        p+=5+l
    if done: break
h=parse_hello(buf[:p+5+l]);
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3]+'/cert.pem',sys.argv[3]+'/key.pem'); ctx.set_alpn_protocols(['h2','http/1.1'])
r={'hello':h}
try:
    t=ctx.wrap_socket(c,server_side=True); r['server_alpn']=t.selected_alpn_protocol(); r['tls']=t.version(); r['cipher']=t.cipher()[0]
    d=b''
    while len(d)<24+9:
        x=t.recv(4096)
        if not x: break
        d+=x
    r['first_app_bytes']=d[:200].hex()
    if d.startswith(b'PRI * HTTP/2.0'):
        f=d[24:]; ln=int.from_bytes(f[:3],'big'); typ=f[3]
        if typ==4:
            pl=f[9:9+ln]; r['h2_settings']=[(int.from_bytes(pl[i:i+2],'big'),int.from_bytes(pl[i+2:i+6],'big')) for i in range(0,len(pl),6)]
        rest=f[9+ln:]
        if len(rest)>=9 and rest[3]==8: r['h2_window_update']=int.from_bytes(rest[9:13],'big')&0x7fffffff
except Exception as e: r['tls_err']=repr(e)
open(out,'w').write(json.dumps(r)); print(json.dumps({k:v for k,v in r.items() if k!='hello'}))
for k in ['sni','alpn','ciphers','extensions','curves','sigalgs','supported_versions','ja3','ja3_hash','ja4','raw_len']: print(k,h[k])
print('ext_lens',{k:len(v)//2 for k,v in h['ext_detail'].items()})
