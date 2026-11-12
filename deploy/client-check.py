"""Bounded local-only client check. Never writes/prints proxy credentials in logs."""
import subprocess,tempfile,time,json,socket,argparse
from datetime import datetime, timezone
from pathlib import Path
import yaml
BINARY=Path(r'C:\Program Files\Clash Verge\verge-mihomo.exe')
SOURCES=[('entry-a3',Path(r'C:\path\to\entry-a3-client.yaml'),119),('entry-a5',Path(r'D:\ops_mcp\entry-a5-25390-mieru.yaml'),123)]
parser=argparse.ArgumentParser()
parser.add_argument('--node', choices=['entry-a3','entry-a5'])
args=parser.parse_args()
failed=False
for name,src,_ in SOURCES:
    if args.node and name != args.node: continue
    started=datetime.now(timezone.utc).isoformat()
    data=yaml.safe_load(src.read_text(encoding='utf-8'))
    proxies=[p for p in data.get('proxies',[]) if p.get('type')=='mieru']
    if len(proxies)!=1: raise RuntimeError('Expected one test proxy: '+name)
    proxy=dict(proxies[0]);proxy['name']='AUDIT_TEST'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='audit-client-',dir=Path(__file__).parent) as tmp:
        cfg=Path(tmp)/'config.yaml'
        cfg.write_text(yaml.safe_dump({'mixed-port':port,'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule','log-level':'silent','ipv6':False,'dns':{'enable':False},'proxies':[proxy],'rules':['MATCH,AUDIT_TEST']}),encoding='utf-8')
        check=subprocess.run([str(BINARY),'-t','-d',tmp,'-f',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW,timeout=15)
        if check.returncode: raise RuntimeError('Client syntax validation failed: '+name)
        child=subprocess.Popen([str(BINARY),'-d',tmp,'-f',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            ready=False
            for i in range(40):
                if child.poll() is not None: break
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):ready=True;break
                except OSError:time.sleep(.1)
            if not ready:raise RuntimeError('Local test listener failed: '+name)
            result=subprocess.run(['curl.exe','--silent','--show-error','--fail','--proxy',f'http://127.0.0.1:{port}','--connect-timeout','10','--max-time','60','--limit-rate','64k','--output','NUL','--write-out','%{http_code} %{size_download} %{time_total}',f'https://speed.cloudflare.com/__down?bytes=1048576&audit={name}'],capture_output=True,text=True,timeout=65,creationflags=subprocess.CREATE_NO_WINDOW)
            failed = failed or result.returncode != 0
            print(json.dumps({'node':name,'started_at':started,'client_config_valid':True,'curl_exit':result.returncode,'result':result.stdout,'error':result.stderr[:200]}),flush=True)
            time.sleep(2)
        finally:
            child.terminate()
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

raise SystemExit(1 if failed else 0)
