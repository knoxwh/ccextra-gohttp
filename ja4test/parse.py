import struct,hashlib
GREASE={0x0a0a+0x1010*i for i in range(16)}
def parse_hello(rec):
    # rec: full TLS record(s) bytes starting with 0x16
    hs=b''; p=0
    while p+5<=len(rec) and rec[p]==0x16:
        l=struct.unpack('>H',rec[p+3:p+5])[0]; hs+=rec[p+5:p+5+l]; p+=5+l
    assert hs[0]==1
    b=hs[4:]; ver=struct.unpack('>H',b[:2])[0]; q=34
    sl=b[q]; q+=1+sl
    cl=struct.unpack('>H',b[q:q+2])[0]; q+=2; ciphers=[struct.unpack('>H',b[q+i:q+i+2])[0] for i in range(0,cl,2)]; q+=cl
    ml=b[q]; q+=1+ml
    el=struct.unpack('>H',b[q:q+2])[0]; q+=2; end=q+el
    exts=[];sni=None;alpn=[];curves=[];pf=[];sig=[];sv=[];detail={}
    while q<end:
        t,l=struct.unpack('>HH',b[q:q+4]); d=b[q+4:q+4+l]; q+=4+l; exts.append(t); detail[t]=d.hex()
        if t==0: sni=d[5:].decode()
        elif t==16:
            r=2
            while r<len(d): n=d[r]; alpn.append(d[r+1:r+1+n].decode()); r+=1+n
        elif t==10: curves=[struct.unpack('>H',d[2+i:4+i])[0] for i in range(0,struct.unpack('>H',d[:2])[0],2)]
        elif t==11: pf=list(d[1:1+d[0]])
        elif t==13: sig=[struct.unpack('>H',d[2+i:4+i])[0] for i in range(0,struct.unpack('>H',d[:2])[0],2)]
        elif t==43: sv=[struct.unpack('>H',d[1+i:3+i])[0] for i in range(0,d[0],2)]
    ng=lambda xs:[x for x in xs if x not in GREASE]
    c,e=ng(ciphers),ng(exts)
    ja3s=f"{ver},{'-'.join(map(str,c))},{'-'.join(map(str,e))},{'-'.join(map(str,ng(curves)))},{'-'.join(map(str,pf))}"
    v=max(ng(sv)) if sv else ver
    vm={0x0304:'13',0x0303:'12',0x0302:'11',0x0301:'10'}[v]
    a=(alpn[0][0]+alpn[0][-1]) if alpn else '00'
    pre=f"t{vm}{'d' if sni else 'i'}{len(c):02d}{len(e):02d}{a}"
    cs=','.join(sorted(f'{x:04x}' for x in c))
    es=','.join(sorted(f'{x:04x}' for x in e if x not in (0,16)))
    ss=','.join(f'{x:04x}' for x in ng(sig))
    h=lambda s:hashlib.sha256(s.encode()).hexdigest()[:12]
    ja4=f"{pre}_{h(cs)}_{h(es+('_'+ss if ss else ''))}"
    return dict(sni=sni,alpn=alpn,ciphers=[f'{x:04x}' for x in ciphers],extensions=exts,curves=curves,point_formats=pf,
        sigalgs=[f'{x:04x}' for x in sig],supported_versions=[f'{x:04x}' for x in sv],ja3=ja3s,ja3_hash=hashlib.md5(ja3s.encode()).hexdigest(),
        ja4=ja4,ja4_r=f"{pre}_{cs}_{es}_{ss}",raw_len=len(rec),ext_detail={k:(v if k not in (41,) else '<psk>') for k,v in detail.items()})
