import socket,struct,time
for ifn in ('ethsh0','etentryb20'):
 pass
socks=[]
for ifn in ('ethsh0','etentryb20'):
 s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3)); s.bind((ifn,0)); s.settimeout(.2); socks.append((ifn,s))
end=time.time()+8
while time.time()<end:
 for ifn,s in socks:
  try:b=s.recv(65535)
  except socket.timeout:continue
  if len(b)<54 or b[12:14]!=b'\x08\x00':continue
  ihl=(b[14]&15)*4
  if b[23]!=6:continue
  src=socket.inet_ntoa(b[26:30]);dst=socket.inet_ntoa(b[30:34]);off=(b[14+ihl+12]>>4)*4;sp,dp,seq,ack,fl,win=struct.unpack('!HHIIHH',b[14+ihl:14+ihl+16])
  if sp==19091 or dp==19091: print(ifn,src,sp,'>',dst,dp,'f',fl,'len',len(b)-(14+ihl+off),flush=True)