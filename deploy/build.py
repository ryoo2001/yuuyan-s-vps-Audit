"""Build audited MCP requests for the NEW traffic-audit namespace only."""
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('hosts',nargs='+');p.add_argument('--update',action='store_true');args=p.parse_args()
requests=[]
for host in args.hosts:
    config=json.loads((ROOT/'config'/f'{host}.json').read_text())
    command=['set -eu','umask 077']
    if not args.update:
        command += ['test ! -e /etc/traffic-audit/config.json','test ! -e /usr/local/libexec/traffic-audit','test ! -e /etc/systemd/system/traffic-audit.service']
    command += ['install -d -m 700 /etc/traffic-audit /var/lib/traffic-audit','install -d -m 750 /usr/local/libexec/traffic-audit']
    files={f'/usr/local/libexec/traffic-audit/{name}':(ROOT/name).read_bytes() for name in ['audit.py','capture.py','query.py','transport.py','presentation.py','rates.py']}
    files['/etc/traffic-audit/config.json']=(ROOT/'config'/f'{host}.json').read_bytes()
    unit=(ROOT/'deploy/traffic-audit.service').read_text()
    if config['mode']=='terminal':
        unit=unit.replace('CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN','CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH')
    files['/etc/systemd/system/traffic-audit.service']=unit.encode()
    for remote,data in files.items():
        text=data.decode().replace('\r\n','\n')
        text=text.rstrip('\n')+'\n'
        digest=hashlib.sha256(text.encode()).hexdigest()
        marker='AUDIT_FILE_'+digest[:20]
        assert marker not in text
        command += [f"cat > '{remote}' <<'{marker}'",text.rstrip('\n'),marker,f"printf '%s  %s\\n' '{digest}' '{remote}' | sha256sum -c -"]
    command += ['chmod 600 /etc/traffic-audit/config.json','chmod 750 /usr/local/libexec/traffic-audit/*.py','chmod 644 /etc/systemd/system/traffic-audit.service',
      "python3 - <<'AUDIT_COMPILE'\nfrom pathlib import Path\nfor p in Path('/usr/local/libexec/traffic-audit').glob('*.py'): compile(p.read_text(),str(p),'exec')\nAUDIT_COMPILE",
      '/usr/bin/python3 /usr/local/libexec/traffic-audit/audit.py --check',
      'systemd-analyze verify /etc/systemd/system/traffic-audit.service','systemctl daemon-reload',
      'systemctl restart traffic-audit.service' if args.update else 'systemctl enable --now traffic-audit.service',
      'sleep 3','systemctl is-active traffic-audit.service',
      'systemctl show traffic-audit.service -p MainPID -p ActiveEnterTimestamp -p MemoryCurrent -p NRestarts',
      "python3 - <<'AUDIT_HEALTH'\nimport json,time\nfrom pathlib import Path\nh=json.loads(Path('/var/lib/traffic-audit/health.json').read_text());m=h['metrics']\nprint(json.dumps({'node':h['node'],'status':h['status'],'warnings':h['warnings'],'errors':m.get('errors'),'queue_dropped':m.get('queue_dropped'),'capture':{k:{n:v.get(n) for n in ['status','packets_received','packets_dropped','packets_if_dropped']} for k,v in m['capture'].items()}}))\nraise SystemExit(1 if h['status']=='error' else 0)\nAUDIT_HEALTH"]
    requests.append({'tool':'ops_ssh_exec','args':{'hostId':host,'command':'\n'.join(command),'maxChars':12000,'timeoutMs':60000}})
(ROOT/'deploy/requests.json').write_text(json.dumps(requests))
print('Built audited requests for: '+', '.join(args.hosts))
