import fs from 'node:fs/promises';
import net from 'node:net';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
const require=createRequire('D:/ops_mcp/package.json');
const {Client}=require('ssh2');
const root='D:/vps_Audit/client';
const pins={
 'legacy-center':'AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEexampleEXAMPLEexampleEXAMPLEexampleEXA'
};
const registry=JSON.parse(await fs.readFile('D:/ops_mcp/hosts.json','utf8'));
async function options(id){
 const h=registry.hosts.find(x=>x.id===id);
 if(!h)throw new Error('host_not_configured');
 const pin=Buffer.from(pins[id],'base64');
 const o={host:h.host,port:h.port??registry.sshPort,username:h.user,password:h.sshPassword,
  readyTimeout:15000,keepaliveInterval:15000,keepaliveCountMax:3,
  algorithms:{serverHostKey:['ssh-ed25519']},
  hostVerifier:key=>key.length===pin.length&&crypto.timingSafeEqual(key,pin)};
 if(h.sshKeyPath)o.privateKey=await fs.readFile(h.sshKeyPath);
 return o;
}
const centerOptions=await options('legacy-center');
let center,ready=false,shutting=false,timer,sockets=new Set();
async function status(state){await fs.writeFile(root+'/status.json',JSON.stringify({pid:process.pid,state,host:'127.0.0.1',port:13306,via:'direct-ssh',databaseHost:'legacy-center',at:new Date().toISOString()}));}
function disconnect(){ready=false;for(const s of sockets)s.destroy();sockets.clear();center?.destroy();}
function lost(){
 if(shutting||timer)return;
 disconnect();status('reconnecting').catch(()=>{});
 timer=setTimeout(()=>{timer=undefined;connect();},5000);
}
function fail(e){
 if(e.level==='client-authentication'||e.message?.includes('Host denied')){
  shutting=true;disconnect();status('authentication_or_host_key_rejected').finally(()=>process.exit(1));
 }else lost();
}
function connect(){
 if(shutting)return;
 center=new Client();
 center.on('error',fail).on('close',lost);
 center.once('ready',()=>{ready=true;status('ready').catch(()=>{});});
 center.connect(centerOptions);
}

const server=net.createServer(socket=>{
 if(!ready){socket.destroy();return;}
 sockets.add(socket);
 socket.on('error',()=>socket.destroy()).on('close',()=>sockets.delete(socket));
 center.forwardOut('127.0.0.1',0,'127.0.0.1',3306,(err,remote)=>{
  if(err||socket.destroyed){remote?.destroy();socket.destroy();return;}
  remote.on('error',()=>socket.destroy()).on('close',()=>socket.destroy());
  socket.on('close',()=>remote.destroy());
  socket.pipe(remote).pipe(socket);
 });
});
server.on('error',()=>{shutting=true;disconnect();status('local_port_unavailable').finally(()=>process.exit(1));});
server.listen(13306,'127.0.0.1',()=>{status('connecting').catch(()=>{});connect();});
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{shutting=true;clearTimeout(timer);disconnect();server.close();status('stopped').finally(()=>process.exit(0));});
