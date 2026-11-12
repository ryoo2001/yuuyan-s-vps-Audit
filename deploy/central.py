import base64,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
image='docker.io/library/mysql@sha256:80f4933e3835f9dc4d35a28ec500d7986cb4414e6c6821c5461239cb7beb8995'
def files_code(mapping):
    rows=[]
    for local,remote in mapping.items():
        value=base64.b64encode((ROOT/local).read_bytes()).decode()
        rows.append(f"p=Path({remote!r});p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.write_bytes(base64.b64decode({value!r}));p.chmod(0o600)")
    return '\n'.join(rows)
def request(host,code,timeout=300000):
    return {'tool':'ops_ssh_exec','args':{'hostId':host,'command':code,'maxChars':4000,'timeoutMs':timeout}}
if sys.argv[1]=='center':
    mapping={f'central/{name}':f'/usr/local/libexec/traffic-central/{name}' for name in ['model.py','receive.py','init.py','prune.py','views.sql','storage.py','region.py','tier_policy.py','tiering.py','archive.py','monthbook.py']}
    mapping.update({'presentation.py':'/usr/local/libexec/traffic-central/presentation.py','query.py':'/usr/local/libexec/traffic-central/source_query.py'})
    mapping.update({'central/mysql.cnf':'/etc/traffic-central/mysql.cnf','central/traffic-central-prune.service':'/etc/systemd/system/traffic-central-prune.service','central/traffic-central-prune.timer':'/etc/systemd/system/traffic-central-prune.timer'})
    py="import base64,os,secrets\nfrom pathlib import Path\nos.umask(0o077)\n"+files_code(mapping)+"\nfor d in ['mysql','run']:\n Path('/var/lib/traffic-central/'+d).mkdir(parents=True,exist_ok=True,mode=0o700)\np=Path('/etc/traffic-central/root-password')\nif not p.exists(): p.write_text(secrets.token_urlsafe(40));p.chmod(0o600)\n"
    script="set -eu\npython3 - <<'PY'\n"+py+"PY\n"
    script+='chmod 644 /etc/traffic-central/mysql.cnf\n'
    script+=f'docker run --rm --network none --memory=256m --memory-swap=256m -v /etc/traffic-central/mysql.cnf:/etc/mysql/conf.d/traffic.cnf:ro --entrypoint mysqld {image} --validate-config\n'
    script+='if docker inspect traffic-mysql >/dev/null 2>&1; then echo existing_container_refused; exit 1; fi\n'
    script+=f'''docker run -d --name traffic-mysql --network host --restart unless-stopped --memory=512m --memory-swap=512m --cpus=0.5 --pids-limit=128 --log-driver=local --log-opt max-size=5m --log-opt max-file=2 -e MYSQL_ROOT_PASSWORD_FILE=/run/secrets/root-password -e MYSQL_ROOT_HOST=localhost -e MYSQL_INITDB_SKIP_TZINFO=1 -v /etc/traffic-central/root-password:/run/secrets/root-password:ro -v /etc/traffic-central/mysql.cnf:/etc/mysql/conf.d/traffic.cnf:ro -v /var/lib/traffic-central/mysql:/var/lib/mysql -v /var/lib/traffic-central/run:/var/run/mysqld {image} --bind-address=127.0.0.1 --mysqlx=OFF\n'''
    script+='python3 /usr/local/libexec/traffic-central/init.py\nsystemctl daemon-reload\nsystemctl enable --now traffic-central-prune.timer\nss -lnt \'( sport = :3306 or sport = :33060 )\'\ndocker stats --no-stream traffic-mysql\nfree -m\n'
    req=[request('legacy-center',script)]
else: raise SystemExit('unknown stage')
p=ROOT/'deploy'/('central-'+sys.argv[1]+'.json');p.write_text(json.dumps(req),encoding='utf8');print(p)
