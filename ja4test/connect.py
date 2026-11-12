# Minimal one-shot HTTP CONNECT proxy for run.sh VIA_CONNECT=1.
import socket,sys,threading
port=int(sys.argv[1])
ls=socket.socket(); ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); ls.bind(('127.0.0.1',port)); ls.listen(1)
c,_=ls.accept(); h=b''
while b'\r\n\r\n' not in h: h+=c.recv(4096)
line=h.split(b'\r\n')[0].decode(); print('proxy got:',line)
host,p=line.split()[1].rsplit(':',1); u=socket.create_connection((host,int(p)))
c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
def cp(a,b):
    try:
        while (d:=a.recv(65536)): b.sendall(d)
    except OSError: pass
    for s in (a,b):
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
threading.Thread(target=cp,args=(u,c),daemon=True).start(); cp(c,u)
