import socket,struct,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3)); s.bind(('etentryb20',0)); s.settimeout(0.5); end=time.time()+8
while time.time()<end:
 try: b=s.recv(65535)
 except socket.timeout: continue
 if len(b)<54 or b[12:14]!=b'\x08\x00': continue
 ihl=(b[14]&15)*4
 if b[23]!=6: continue
 src=socket.inet_ntoa(b[26:30]); dst=socket.inet_ntoa(b[30:34]); off=(b[14+ihl+12]>>4)*4; sp,dp,seq,ack,fl,win=struct.unpack('!HHIIHH',b[14+ihl:14+ihl+16])
 if sp==19091 or dp==19091: print(src,sp,'>',dst,dp,'flags',fl,'len',len(b)-(14+ihl+off),flush=True)