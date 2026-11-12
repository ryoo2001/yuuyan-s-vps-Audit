"""Current calendar totals; cold raw facts remain outside MySQL."""
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import time
import storage

VERSION=1
KINDS={'samples':('event_id',),'traffic_rollup':('day_start','source_ip','node','site')}


def guard_statements(database,prefix):
    return {prefix+kind+'_calendar_bd':'CREATE DEFINER=`root`@`localhost` TRIGGER '+storage.identifier(database)+'.'+storage.identifier(prefix+kind+'_calendar_bd')
        +' BEFORE DELETE ON '+storage.table(database,prefix,kind)+' FOR EACH ROW BEGIN IF COALESCE(@audit_calendar_verified,0)<>1 THEN '
        +"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='calendar_accounting_required';END IF;END" for kind in KINDS}


def month(now=None):
    from archive import TZ
    date=datetime.fromtimestamp(time.time() if now is None else now,TZ).replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    return date.strftime('%Y-%m'),int(date.timestamp())


def json_value(value):return json.dumps(value,ensure_ascii=False,separators=(',',':'))


def order_key(kind,data):
    return [data['ts' if kind=='samples' else 'latest_ts']]+[data[k] for k in KINDS[kind]]


def install(db,database,prefix):
    meta=storage.table(database,'','audit_schema')
    with db.cursor() as c:
        c.execute('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',(database,'audit_schema'))
        columns={r[0] for r in c.fetchall()}
        additions={'calendar_version':'INT NOT NULL DEFAULT 0','calendar_samples_cursor':'LONGTEXT NULL','calendar_rollup_cursor':'LONGTEXT NULL'}
        missing=[k for k in additions if k not in columns]
        if missing:c.execute('ALTER TABLE '+meta+' '+','.join('ADD COLUMN '+storage.identifier(k)+' '+additions[k] for k in missing))
        c.execute('CREATE TABLE IF NOT EXISTS '+storage.table(database,'','traffic_calendar')+' ('
            'namespace VARCHAR(32) NOT NULL,month_start BIGINT NOT NULL,source_ip VARCHAR(45) NOT NULL,node VARCHAR(64) NOT NULL,site VARCHAR(253) NOT NULL,'
            'upload_bytes DECIMAL(38,0) NOT NULL,download_bytes DECIMAL(38,0) NOT NULL,fact_rows BIGINT NOT NULL,latest_ts DOUBLE NOT NULL,'
            'PRIMARY KEY(month_start,namespace,source_ip,node,site)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')
        c.execute('CREATE TABLE IF NOT EXISTS '+storage.table(database,'','archive_receipts')+' ('
            'digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,month_start BIGINT NOT NULL,filename VARCHAR(255) NOT NULL,'
            'KEY by_month(month_start)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')
        c.execute('UPDATE '+meta+' SET calendar_version=1 WHERE namespace=%s',(prefix,))
        guards=guard_statements(database,prefix)
        c.execute('SELECT TRIGGER_NAME,ACTION_STATEMENT,DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s AND TRIGGER_NAME IN ('+','.join('%s'for _ in guards)+')',(database,*guards))
        import re
        existing=c.fetchall()
        for name,body,definer in existing:
            assert re.sub(r'\s+',' ',body).strip()==re.sub(r'\s+',' ',guards[name].split(' FOR EACH ROW ',1)[1]).strip() and definer=='root@localhost','calendar_guard_changed'
        seen={r[0]for r in existing}
        for name,ddl in guards.items():
            if name not in seen:c.execute(ddl)
    db.commit()


def cursor_column(kind):return 'calendar_samples_cursor' if kind=='samples' else 'calendar_rollup_cursor'


def cursor_expressions(database,prefix,kind):
    columns=('ts',*KINDS[kind]) if kind=='samples' else ('latest_ts',*KINDS[kind])
    selected='(SELECT '+cursor_column(kind)+' FROM '+storage.table(database,'','audit_schema')+" WHERE namespace='"+prefix+"')"
    result=[]
    for i,name in enumerate(columns):
        expression="JSON_UNQUOTE(JSON_EXTRACT("+selected+",'$["+str(i)+"]'))"
        result.append('('+expression+'+0e0)' if name in ('ts','latest_ts','day_start') else expression+' COLLATE utf8mb4_bin')
    return columns,result


def suppressed_sql(database,prefix,kind):
    columns,values=cursor_expressions(database,prefix,kind)
    return '('+','.join(storage.identifier(k) for k in columns)+')<=('+','.join(values)+')'


class Index:
    def __init__(self,store,database):
        self.store=store;self.database=database;self.label,self.start=month()
        folder=store.state_root/database;folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(str(folder/'.calendar-index.sqlite'))
        self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS applied(digest TEXT PRIMARY KEY,month_start INTEGER) WITHOUT ROWID')
        self.db.execute('CREATE TABLE IF NOT EXISTS facts(k TEXT PRIMARY KEY,namespace TEXT,kind TEXT,seq INTEGER,written INTEGER,body TEXT) WITHOUT ROWID')
        self.db.execute('CREATE TABLE IF NOT EXISTS state(k TEXT PRIMARY KEY,v TEXT) WITHOUT ROWID')
        old=self.db.execute("SELECT v FROM state WHERE k='month'").fetchone()
        if old and old[0]!=self.label:
            self.db.execute('DELETE FROM facts');self.db.execute('DELETE FROM applied')
        self.db.execute("INSERT OR REPLACE INTO state VALUES('month',?)",(self.label,));self.db.commit()
        for path in folder.glob('.calendar-index.sqlite*'):path.chmod(0o600)

    def apply_blob(self,digest,filename,blob):
        from archive import checked_chunk
        header,rows=checked_chunk(blob,filename)
        if header['database']!=self.database:raise ValueError('calendar_archive_database_mismatch')
        kind=header['logical_table']
        if kind in KINDS:
            for row in rows:
                raw=dict(zip(header['columns'],row));wanted={*KINDS[kind],*storage.KEYS,'ts' if kind=='samples' else 'latest_ts','upload_bytes','download_bytes','_seq'}
                data={k:v for k,v in raw.items() if k in wanted};key=json_value([header['namespace'],kind]+[data[k] for k in KINDS[kind]])
                self.db.execute('INSERT INTO facts VALUES(?,?,?,?,?,?) ON CONFLICT(k) DO UPDATE SET seq=excluded.seq,written=excluded.written,body=excluded.body '
                    'WHERE excluded.seq>facts.seq OR (excluded.seq=facts.seq AND excluded.written>facts.written)',
                    (key,header['namespace'],kind,int(data.get('_seq') or 0),header['written_ns'],json_value(data)))
        self.db.execute('INSERT OR IGNORE INTO applied VALUES(?,?)',(digest,self.start))

    def sync(self,db):
        with db.cursor() as c:
            c.execute('SELECT digest,filename FROM '+storage.table(self.database,'','archive_receipts')+' WHERE month_start=%s',(self.start,));receipts=c.fetchall()
        done={r[0] for r in self.db.execute('SELECT digest FROM applied')}
        pending=[r for r in receipts if r[0] not in done]
        if not pending:return
        missing=[]
        try:
            for digest,filename in pending:
                path=self.store.root/self.database/self.label/filename
                if path.is_file():self.apply_blob(digest,filename,path.read_bytes())
                else:missing.append((digest,filename))
            if missing:
                wanted=dict(missing)
                for filename,blob in self.store.chunks(self.database,self.label):
                    digest=filename.split('.')[-3]
                    if digest in wanted:self.apply_blob(digest,filename,blob);wanted.pop(digest)
                if wanted:raise ValueError('committed_calendar_archive_missing')
            self.db.commit()
        except Exception:self.db.rollback();raise

    def previous(self,prefix,kind,data):
        key=json_value([prefix,kind]+[data[k] for k in KINDS[kind]])
        row=self.db.execute('SELECT body FROM facts WHERE k=?',(key,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self):self.db.close()


def index_for(db,store,database):
    if not hasattr(store,'calendar_indexes'):store.calendar_indexes={}
    cached=store.calendar_indexes.get(database)
    if cached and cached.label!=month()[0]:cached.close();cached=None
    if cached is None:cached=Index(store,database);store.calendar_indexes[database]=cached
    cached.sync(db);return cached


def contribution(data):
    group=tuple(data.get(k) or '未识别' for k in storage.KEYS)
    return group,(int(data.get('upload_bytes') or 0),int(data.get('download_bytes') or 0),1)


def prepare(db,store,database,prefix,kind,rows,files):
    if kind not in KINDS:return None
    from archive import specification,TZ
    index=index_for(db,store,database);columns,keys,stamp=specification(kind);deltas=defaultdict(lambda:[0,0,0,0.])
    for row in rows:
        data=dict(zip(columns,row))
        if datetime.fromtimestamp(data[stamp],TZ).strftime('%Y-%m')!=index.label:continue
        prior=index.previous(prefix,kind,data)
        if prior is not None and int(prior.get('_seq') or 0)>int(data.get('_seq') or 0):continue
        if prior:
            group,values=contribution(prior)
            for i,v in enumerate(values):deltas[group][i]-=v
        group,values=contribution(data)
        for i,v in enumerate(values):deltas[group][i]+=v
        deltas[group][3]=max(deltas[group][3],data[stamp])
    with db.cursor() as c:
        for group,(up,down,count,latest) in deltas.items():
            if up or down or count or latest:
                c.execute('INSERT INTO '+storage.table(database,'','traffic_calendar')+' VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE '
                    'upload_bytes=upload_bytes+VALUES(upload_bytes),download_bytes=download_bytes+VALUES(download_bytes),fact_rows=fact_rows+VALUES(fact_rows),latest_ts=GREATEST(latest_ts,VALUES(latest_ts))',
                    (prefix,index.start,*group,up,down,count,latest))
        c.execute('DELETE FROM '+storage.table(database,'','traffic_calendar')+' WHERE namespace=%s AND month_start=%s AND fact_rows=0',(prefix,index.start))
        for f in files:
            if f['month']==index.label:
                c.execute('INSERT INTO '+storage.table(database,'','archive_receipts')+' VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE digest=VALUES(digest)',(f['sha256'],index.start,Path(f['file']).name))
        column=cursor_column(kind);meta=storage.table(database,'','audit_schema')
        c.execute('SELECT '+column+' FROM '+meta+' WHERE namespace=%s FOR UPDATE',(prefix,));old=json.loads(c.fetchone()[0] or '[]')
        newest=max(order_key(kind,dict(zip(columns,row))) for row in rows)
        if not old or tuple(newest)>tuple(old):c.execute('UPDATE '+meta+' SET '+column+'=%s WHERE namespace=%s',(json_value(newest),prefix))
    return index


def bootstrap(db,store,database,prefixes):
    """Explicit current-month repair. Caller holds the archive file lock."""
    from archive import checked_chunk
    index=Index(store,database)
    with db.cursor() as c:
        c.execute('SELECT COUNT(*) FROM '+storage.table(database,'','archive_receipts'))
        if c.fetchone()[0]:raise ValueError('calendar_bootstrap_already_applied')
    chunks=[]
    for filename,blob in store.chunks(database,index.label):
        header,rows=checked_chunk(blob,filename);digest=filename.split('.')[-3]
        if header['namespace'] not in prefixes:raise ValueError('unexpected_calendar_namespace')
        index.apply_blob(digest,filename,blob);chunks.append((digest,index.start,filename))
    index.db.commit();groups=defaultdict(lambda:[0,0,0,0.]);cursors={}
    for prefix,kind,body in index.db.execute('SELECT namespace,kind,body FROM facts'):
        data=json.loads(body);group,values=contribution(data);target=groups[(prefix,*group)]
        for i,v in enumerate(values):target[i]+=v
        key=order_key(kind,data);target[3]=max(target[3],key[0]);cursors[(prefix,kind)]=max(cursors.get((prefix,kind),key),key)
    db.begin()
    try:
        with db.cursor() as c:
            for key,values in groups.items():c.execute('INSERT INTO '+storage.table(database,'','traffic_calendar')+' VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',(key[0],index.start,*key[1:],*values))
            if chunks:c.executemany('INSERT INTO '+storage.table(database,'','archive_receipts')+' VALUES(%s,%s,%s)',chunks)
            for (prefix,kind),key in cursors.items():c.execute('UPDATE '+storage.table(database,'','audit_schema')+' SET '+cursor_column(kind)+'=%s WHERE namespace=%s',(json_value(key),prefix))
        db.commit()
    except Exception:db.rollback();raise
    finally:index.close()
    return {'database':database,'month':index.label,'archive_chunks':len(chunks),'groups':len(groups),'upload_bytes':sum(v[0] for v in groups.values()),'download_bytes':sum(v[1] for v in groups.values())}


def retire(db,store,databases):
    start=month()[1]
    with db.cursor() as c:
        for database in databases:
            for name in ('traffic_calendar','archive_receipts'):c.execute('DELETE FROM '+storage.table(database,'',name)+' WHERE month_start<%s',(start,))
