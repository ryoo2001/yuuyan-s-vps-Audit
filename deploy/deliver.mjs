import fs from 'node:fs/promises';
import {generateKeyPairSync,privateDecrypt,constants} from 'node:crypto';
import {Client} from 'file:///D:/ops_mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import {StdioClientTransport} from 'file:///D:/ops_mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:4096});
const pub=Buffer.from(publicKey.export({type:'spki',format:'pem'})).toString('base64');
const command=`python3 - <<'PY'\nimport base64,json,subprocess\nfrom pathlib import Path\nc=json.loads(Path('/etc/traffic-central/reader.json').read_text())\nc={k:c[k] for k in ['user','password','database']}\nc.update(host='127.0.0.1',port=13306)\np=Path('/run/traffic-central-delivery.pub')\ntry:\n p.write_bytes(base64.b64decode('${pub}'))\n r=subprocess.run(['openssl','pkeyutl','-encrypt','-pubin','-inkey',str(p),'-pkeyopt','rsa_padding_mode:oaep','-pkeyopt','rsa_oaep_md:sha256'],input=json.dumps(c).encode(),capture_output=True,check=True)\n print(base64.b64encode(r.stdout).decode())\nfinally:\n p.unlink(missing_ok=True)\nPY`;
const transport=new StdioClientTransport({command:process.execPath,args:['D:/ops_mcp/dist/index.js','--stdio'],cwd:'D:/ops_mcp',env:{...process.env,MCP_CONFIG_FILE:'D:/ops_mcp/hosts.json',MCP_TOOL_PROFILE:'full'},stderr:'pipe'});
const client=new Client({name:'traffic-audit-credential-delivery',version:'1.0.0'});
try{
 await client.connect(transport);
 const result=await client.callTool({name:'ops_ssh_exec',arguments:{hostId:'legacy-center',command,maxChars:2000,timeoutMs:30000}});
 const d=JSON.parse(result.content.find(c=>c.type==='text').text);
 if(result.isError||d.code!==0) throw new Error('encrypted_delivery_failed');
 const plaintext=privateDecrypt({key:privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},Buffer.from(d.stdout.trim(),'base64'));
 const cfg=JSON.parse(plaintext.toString());
 if(cfg.user!=='audit_ro'||cfg.database!=='region-a'||cfg.host!=='127.0.0.1')throw new Error('unexpected_reader');
 await fs.writeFile('D:/vps_Audit/client/connection.json',JSON.stringify(cfg,null,2));
 plaintext.fill(0);
 console.log('Read-only connection saved in protected local directory; no credentials printed.');
}finally{await client.close();}
