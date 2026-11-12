"""Bounded central cold storage. Files are durable before database deletion."""
import argparse
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tarfile
import tempfile
import time

from model import TABLES
import storage
import monthbook
from tier_policy import ARCHIVE_ROOT, HOT_DAYS, ONLINE_DAYS, metadata

TZ = timezone(timedelta(hours=8))
ROLLUP_COLUMNS = 'day_start source_ip node site upload_bytes download_bytes latest_ts'.split()
MONTH_RE = re.compile(r'20[0-9]{2}-(?:0[1-9]|1[0-2])')
BATCH = 500
# Resealing rewrites and re-reads a whole month over the archive mount, so a
# sealed month absorbs late parts at most once a day.
RESEAL_SECONDS = 86400


def specification(name):
    if name == 'traffic_rollup':
        return ROLLUP_COLUMNS, ROLLUP_COLUMNS[:4], 'latest_ts'
    columns, keys, stamp = TABLES[name]
    if not stamp:
        raise ValueError('configuration_is_not_expiring_fact')
    return columns + ['_seq'], keys, stamp


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _fsync_directory(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def checked_chunk(blob, name):
    match = re.fullmatch(r'([a-z][a-z0-9_]*?).([0-9a-f]{64}).jsonl.gz', Path(name).name)
    if not match:
        raise ValueError('invalid_archive_chunk_name')
    raw = gzip.decompress(blob)
    if hashlib.sha256(raw).hexdigest() != match[2]:
        raise ValueError('archive_checksum_mismatch')
    lines = raw.splitlines()
    header = json.loads(lines[0])
    if header.get('format') != 'audit-cold-v1' or header['table'] != match[1]:
        raise ValueError('archive_header_mismatch')
    storage.validate(header['database'], (header['namespace'],))
    columns, keys, stamp = specification(header['logical_table'])
    if header['columns'] != columns or header['keys'] != keys or header['stamp'] != stamp:
        raise ValueError('archive_contract_mismatch')
    if header['table'] != header['namespace'] + header['logical_table']:
        raise ValueError('archive_namespace_mismatch')
    rows = [json.loads(line) for line in lines[1:]]
    if len(rows) != header['rows'] or any(len(row) != len(columns) for row in rows):
        raise ValueError('archive_row_count_mismatch')
    return header, rows


class Store:
    def __init__(self, root=ARCHIVE_ROOT, state_root=None):
        self.root = Path(root).resolve()
        config_path=Path(os.environ.get('TRAFFIC_CENTRAL_STORAGE_CONFIG','/etc/traffic-central/storage.json'))
        config=json.loads(config_path.read_text()) if str(self.root)==str(Path(ARCHIVE_ROOT).resolve()) and config_path.exists() else {}
        self.state_root = Path(state_root or os.environ.get(
            'TRAFFIC_CENTRAL_STATE', config.get('state_root',root))).resolve()
        if config.get('mount_source'):
            mounted=False
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields=line.split();separator=fields.index('-')
                if fields[4]==str(self.root) and fields[separator+1] in ('nfs','nfs4') and fields[separator+2]==config['mount_source']:
                    mounted=True
            if not mounted:raise RuntimeError('cold_archive_mount_required')

    def write(self, database, prefix, name, rows, written_ns=None):
        storage.validate(database, (prefix,))
        columns, keys, stamp = specification(name)
        months = defaultdict(list)
        for row in rows:
            month = datetime.fromtimestamp(float(row[columns.index(stamp)]), TZ).strftime('%Y-%m')
            months[month].append(list(row))
        results = []
        for month, selected in months.items():
            header = {'format':'audit-cold-v1', 'database':database, 'namespace':prefix,
                      'table':prefix+name, 'logical_table':name, 'columns':columns,
                      'keys':keys, 'stamp':stamp, 'rows':len(selected),
                      'written_ns':written_ns if written_ns is not None else time.time_ns(),
                      'coverage':'observed_rows_only_no_reconstruction'}
            raw = ('\n'.join([_json(header)] + [_json(row) for row in selected]) + '\n').encode()
            digest = hashlib.sha256(raw).hexdigest()
            filename = prefix+name+'.'+digest+'.jsonl.gz'
            blob = gzip.compress(raw, compresslevel=6, mtime=0)
            target = self.root/database/month
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            if any(q.is_symlink() for q in (self.root, self.root/database, target)):
                raise ValueError('archive_symlink_refused')
            if shutil.disk_usage(target).free < max(32*1024*1024, len(blob)*3):
                raise OSError('archive_free_space_gate')
            destination = target/filename
            descriptor, temporary = tempfile.mkstemp(prefix='.write-', dir=target)
            try:
                with os.fdopen(descriptor, 'wb') as out:
                    out.write(blob); out.flush(); os.fsync(out.fileno())
                actual, actual_rows = checked_chunk(Path(temporary).read_bytes(), filename)
                if actual != header or actual_rows != selected:
                    raise ValueError('archive_roundtrip_mismatch')
                os.replace(temporary, destination); _fsync_directory(target)
            finally:
                if Path(temporary).exists(): Path(temporary).unlink()
            results.append({'month':month, 'file':str(destination.relative_to(self.root)),
                            'rows':len(selected), 'bytes':len(blob), 'sha256':digest})
        return results

    def chunks(self, database, month):
        storage.validate(database, ('',))
        if not MONTH_RE.fullmatch(month): raise ValueError('invalid_archive_month')
        base = self.root/database
        packed = base/(month+'.tar')
        if packed.exists():
            with tarfile.open(packed, 'r|') as tar:
                for entry in tar:
                    if not entry.isfile() or Path(entry.name).name != entry.name:
                        raise ValueError('invalid_archive_member')
                    yield entry.name, tar.extractfile(entry).read()
        folder = base/month
        if folder.exists():
            for path in sorted(folder.glob('*.jsonl.gz')):
                if path.is_symlink(): raise ValueError('archive_symlink_refused')
                yield path.name, path.read_bytes()

    def months(self, database):
        """Month names only; never lists the parts inside a month folder."""
        storage.validate(database, ('',))
        base = self.root/database
        months = set()
        if base.exists():
            for path in base.iterdir():
                month = path.name[:-4] if path.name.endswith('.tar') else path.name
                if MONTH_RE.fullmatch(month): months.add(month)
        return sorted(months)

    def catalog(self, database):
        base = self.root/database
        return [{'month':month, 'packed':(base/(month+'.tar')).is_file(),
                 'pending_parts':len(list((base/month).glob('*.jsonl.gz')))} for month in self.months(database)]

    def seal_due(self, database, month, now=None):
        """Whether a closed month has loose parts worth sealing now."""
        if not MONTH_RE.fullmatch(month): raise ValueError('invalid_archive_month')
        base = self.root/database
        packed = base/(month+'.tar')
        now = time.time() if now is None else now
        if packed.is_file() and 0 <= now-packed.stat().st_mtime < RESEAL_SECONDS:
            return False
        folder = base/month
        return folder.is_dir() and next(folder.glob('*.jsonl.gz'), None) is not None

    def pack(self, database, month):
        storage.validate(database, ('',))
        if not MONTH_RE.fullmatch(month): raise ValueError('invalid_archive_month')
        base = self.root/database; folder = base/month
        parts = list(folder.glob('*.jsonl.gz'))
        if not parts: return {'month':month, 'packed':False, 'reason':'no_new_parts'}
        destination = base/(month+'.tar'); temporary = base/('.'+month+'.pack.tmp')
        projected = sum(p.stat().st_size + 1024 for p in parts) + (destination.stat().st_size if destination.exists() else 0)
        if shutil.disk_usage(base).free < max(32*1024*1024, projected*2):
            raise OSError('archive_pack_free_space_gate')
        names = set()
        try:
            with tarfile.open(temporary, 'w', format=tarfile.PAX_FORMAT) as tar:
                for name, blob in self.chunks(database, month):
                    checked_chunk(blob, name)
                    if name in names: continue
                    names.add(name); info=tarfile.TarInfo(name); info.size=len(blob); info.mode=0o600
                    tar.addfile(info, io.BytesIO(blob))
            temporary.chmod(0o600)
            with temporary.open('r+b') as handle: os.fsync(handle.fileno())
            seen=set()
            with tarfile.open(temporary, 'r|') as tar:
                for member in tar:
                    checked_chunk(tar.extractfile(member).read(),member.name);seen.add(member.name)
            if seen != names: raise ValueError('packed_archive_members_mismatch')
            os.replace(temporary,destination);_fsync_directory(base)
            for path in parts: path.unlink()
            if not any(folder.iterdir()):folder.rmdir()
            _fsync_directory(base)
            return {'month':month,'packed':True,'members':len(names),'bytes':destination.stat().st_size}
        finally:
            if temporary.exists(): temporary.unlink()


def archive_batch(db, store, database, prefix, name, cutoff, limit=BATCH):
    columns, keys, stamp = specification(name)
    physical = storage.table(database,prefix,name)
    quoted = ','.join(storage.identifier(c) for c in columns)
    db.begin()
    try:
        with db.cursor() as c:
            c.execute('SELECT '+quoted+' FROM '+physical+' WHERE '+storage.identifier(stamp)+'<%s ORDER BY '
                      +storage.identifier(stamp)+','+','.join(storage.identifier(k) for k in keys)
                      +' LIMIT %s FOR UPDATE'+('' if name in monthbook.KINDS else ' SKIP LOCKED'),(cutoff,limit))
            rows=c.fetchall()
            if not rows: db.commit(); return {'rows':0,'files':[]}
            files=store.write(database,prefix,name,rows)
            calendar=monthbook.prepare(db,store,database,prefix,name,rows,files) if isinstance(store,Store) else None
            where=' AND '.join(storage.identifier(k)+'=%s' for k in keys)
            guarded_keys=list(keys)
            if '_seq' in columns:
                where+=' AND `_seq`=%s';guarded_keys.append('_seq')
            values=[tuple(row[columns.index(k)] for k in guarded_keys) for row in rows]
            c.execute('SET @audit_archive_verified=1')
            if calendar is not None:c.execute('SET @audit_calendar_verified=1')
            try:
                c.executemany('DELETE FROM '+physical+' WHERE '+where,values)
                if c.rowcount != len(rows): raise ValueError('archive_delete_count_mismatch')
            finally: c.execute('SET @audit_archive_verified=0,@audit_calendar_verified=0')
        db.commit()
        if calendar is not None:calendar.sync(db)
        return {'rows':len(rows),'files':files}
    except Exception:
        db.rollback();raise


def discover(db):
    with db.cursor() as c:
        c.execute("SELECT TABLE_SCHEMA FROM information_schema.TABLES WHERE TABLE_NAME='audit_schema' AND TABLE_TYPE='BASE TABLE'")
        databases=[r[0] for r in c.fetchall()]
        result=[]
        for database in databases:
            storage.validate(database,('',))
            c.execute('SELECT namespace,version,ready,archive_policy_version FROM '+storage.table(database,'','audit_schema'))
            for prefix,version,ready,policy_version in c.fetchall():
                if version!=2 or ready!=1 or policy_version!=1:raise ValueError('regional_tier_policy_not_ready')
                storage.validate(database,(prefix,));result.append((database,prefix))
    return result


def run(db,store,budget=20,now=None):
    now=time.time() if now is None else now;cutoff=now-ONLINE_DAYS*86400;deadline=time.monotonic()+budget
    sources=discover(db);report={'policy':metadata(),'cutoff':cutoff,'sources':[],'packed':[]}
    monthbook.retire(db,store,{d for d,_ in sources})
    for database,prefix in sources:
        report['sources'].append({'database':database,'namespace':prefix,'rows':0,'files':0,'archive_bytes':0})
    names=[n for n in TABLES if TABLES[n][2]]+['traffic_rollup']
    # Persist the next source/table before each turn. A slow or failing source
    # cannot monopolize every invocation when the global budget is exhausted.
    jobs=[(item,name) for name in names for item in report['sources']]
    cursor=store.state_root/'.cursor.json';index=0;idle=0
    if cursor.exists():
        try:
            key=json.loads(cursor.read_text())
            index=next((i for i,(item,name) in enumerate(jobs)
                        if [item['database'],item['namespace'],name]==key),0)
        except (ValueError,OSError):report['cursor_warning']='invalid_cursor_restarted'
    while jobs and idle<len(jobs) and time.monotonic()<deadline:
        item,name=jobs[index];index=(index+1)%len(jobs);following,next_name=jobs[index]
        temporary=store.state_root/'.cursor.tmp'
        temporary.write_text(_json([following['database'],following['namespace'],next_name]));temporary.chmod(0o600)
        os.replace(temporary,cursor)
        out=archive_batch(db,store,item['database'],item['namespace'],name,cutoff)
        item['rows']+=out['rows'];item['files']+=len(out['files']);item['archive_bytes']+=sum(f['bytes'] for f in out['files'])
        idle=idle+1 if not out['rows'] else 0
    for database in sorted({d for d,_ in sources}):
        for month in store.months(database):
            date=datetime.strptime(month,'%Y-%m').replace(tzinfo=TZ)
            end=(date.replace(day=28)+timedelta(days=4)).replace(day=1).timestamp()
            # Only a month entirely outside the online window can be sealed. An open
            # month is not listed: that is one directory read of every part per run.
            if end<=cutoff and time.monotonic()<deadline and store.seal_due(database,month,now):
                report['packed'].append({'database':database,**store.pack(database,month)})
    return report


class ExactSum:
    def __init__(self):self.value=0
    def step(self,value):self.value+=int(value or 0)
    def finalize(self):return str(self.value)


@contextmanager
def read_month(store,database,month):
    # Explicit reads use a short-lived SQLite scratch file, never a MySQL schema.
    store.state_root.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(prefix='.query-',dir=store.state_root) as directory:
        db=sqlite3.connect(str(Path(directory)/'rows.sqlite'));db.create_aggregate('sum_exact',1,ExactSum)
        db.execute('CREATE TABLE facts(kind TEXT,k TEXT,seq INTEGER,written INTEGER,source_ip TEXT,node TEXT,site TEXT,up TEXT,down TEXT,total TEXT,body TEXT,PRIMARY KEY(kind,k)) WITHOUT ROWID')
        count=0
        try:
            for filename,blob in store.chunks(database,month):
                header,rows=checked_chunk(blob,filename)
                if header['database']!=database:raise ValueError('archive_database_mismatch')
                for row in rows:
                    data=dict(zip(header['columns'],row));key=_json([header['namespace']]+[data[k] for k in header['keys']])
                    up=int(data.get('upload_bytes') or 0);down=int(data.get('download_bytes') or 0)
                    db.execute('INSERT INTO facts VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(kind,k) DO UPDATE SET '
                        'seq=excluded.seq,written=excluded.written,source_ip=excluded.source_ip,node=excluded.node,site=excluded.site,up=excluded.up,down=excluded.down,total=excluded.total,body=excluded.body '
                        'WHERE excluded.seq>facts.seq OR (excluded.seq=facts.seq AND excluded.written>facts.written)',
                        (header['logical_table'],key,int(data.get('_seq') or 0),header['written_ns'],data.get('source_ip') or '未识别',data.get('node') or '未识别',data.get('site') or '未识别',str(up),str(down),str(up+down),_json(data)))
                    count+=1
            if not count:raise ValueError('requested_month_has_no_archive')
            db.commit();yield db
        finally:db.close()


def query_month(store,database,month,*,kind=None,limit=100,source_ip=None,site=None,node=None):
    if not 1<=limit<=1000:raise ValueError('invalid_archive_query_limit')
    if kind is not None:specification(kind)
    conditions=[];params=[]
    for column,value in [('source_ip',source_ip),('site',site),('node',node)]:
        if value is not None:conditions.append(column+'=?');params.append(value)
    with read_month(store,database,month) as db:
        if kind:
            where='kind=?'+(' AND '+' AND '.join(conditions) if conditions else '')
            rows=[json.loads(r[0]) for r in db.execute('SELECT body FROM facts WHERE '+where+' ORDER BY k LIMIT ?', [kind]+params+[limit+1])]
            result={'rows':rows[:limit],'has_more':len(rows)>limit}
        else:
            where="kind IN ('samples','traffic_rollup')"+(' AND '+' AND '.join(conditions) if conditions else '')
            grouped='SELECT source_ip,node,site,sum_exact(up) u,sum_exact(down) d,sum_exact(total) total FROM facts WHERE '+where+' GROUP BY source_ip,node,site'
            total=db.execute('SELECT sum_exact(up),sum_exact(down),sum_exact(total) FROM facts WHERE '+where,params).fetchone()
            count=db.execute('SELECT COUNT(*) FROM ('+grouped+')',params).fetchone()[0]
            rows=[{'source_ip':r[0],'node':r[1],'site':r[2],'upload_bytes':int(r[3]),'download_bytes':int(r[4]),'total_bytes':int(r[5])} for r in db.execute('SELECT * FROM ('+grouped+') ORDER BY length(total) DESC,total DESC,source_ip,node,site LIMIT ?',params+[limit])]
            result={'rows':rows,'totals':dict(zip(['upload_bytes','download_bytes','total_bytes'],[int(v or 0) for v in total])),'groups_total':count,'truncated':count>limit}
    return {'database':database,'month':month,'storage':'cold_files','explicit_load':True,'imported_into_mysql':False,'warnings':['observed_rows_only; previously deleted detail cannot be recovered; not billing data'],**result}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['run','list','summary','rows','pack'])
    parser.add_argument('--root',default=ARCHIVE_ROOT);parser.add_argument('--database');parser.add_argument('--month')
    parser.add_argument('--table');parser.add_argument('--limit',type=int,default=100)
    parser.add_argument('--source-ip');parser.add_argument('--site');parser.add_argument('--node')
    parser.add_argument('--budget',type=float,default=20);args=parser.parse_args();os.umask(0o077)
    store=Store(args.root);store.root.mkdir(parents=True,exist_ok=True,mode=0o700)
    store.state_root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.environ.get('TRAFFIC_CENTRAL_REQUIRE_MOUNT')=='1' and not os.path.ismount(store.root):
        raise RuntimeError('cold_archive_mount_required')
    import fcntl
    with (store.state_root/'.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX if args.command in ('run','pack') else fcntl.LOCK_SH)
        if args.command=='run':
            import pymysql
            db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
            try:
                with db.cursor() as c:
                    c.execute('SET SESSION max_statement_time=20');c.execute('SET SESSION innodb_lock_wait_timeout=4');c.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
                result=run(db,store,budget=args.budget)
            finally:db.close()
        elif not args.database:parser.error('--database required')
        elif args.command=='list':result=store.catalog(args.database)
        elif not args.month:parser.error('--month required')
        elif args.command=='pack':result=store.pack(args.database,args.month)
        else:
            if args.command=='rows' and not args.table:parser.error('--table required')
            result=query_month(store,args.database,args.month,kind=args.table if args.command=='rows' else None,limit=args.limit,source_ip=args.source_ip,site=args.site,node=args.node)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
