import fs from 'node:fs/promises';
import { Client } from 'file:///D:/ops_mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import { StdioClientTransport } from 'file:///D:/ops_mcp/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';
const transport = new StdioClientTransport({command:process.execPath,args:['D:/ops_mcp/dist/index.js','--stdio'],cwd:'D:/ops_mcp',env:{...process.env,MCP_CONFIG_FILE:'D:/ops_mcp/hosts.json',MCP_TOOL_PROFILE:'full'},stderr:'pipe'});
const client = new Client({name:'traffic-audit-deploy',version:'1.0.0'});
let err=''; transport.stderr?.on('data',data=>{err+=data.toString(); if(err.length>4096)err=err.slice(-4096);});
try {
 await client.connect(transport);
 const requests=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
 const output=[];
 for(const req of requests){
  const result=await client.callTool({name:req.tool??'ops_ssh_exec',arguments:req.args},undefined,{timeout:300000});
  const item={hostId:req.args.hostId,result}; output.push(item);
  console.log(JSON.stringify(item));
  const text=result.content?.find(x=>x.type==='text')?.text;
  let data;try{data=JSON.parse(text);}catch{}
  if(result.isError || (typeof data?.code==='number' && data.code!==0)){process.exitCode=1;break;}
 }
 if(process.argv[3])await fs.writeFile(process.argv[3],JSON.stringify(output,null,2));
} catch(e){console.error(e.message);process.exitCode=1;} finally{await client.close();}
