"""Non-destructive regional tier installation and hot-view projections."""
import hashlib
import re
import time
from model import TABLES
import storage
from tier_policy import HOT_DAYS, ONLINE_DAYS, POLICY_VERSION

POLICY_COLUMNS = {
    'archive_policy_version':'INT NOT NULL DEFAULT 0',
    'hot_days':'TINYINT NOT NULL DEFAULT 7',
    'online_days':'TINYINT NOT NULL DEFAULT 14',
    'tier_updated_at':'DOUBLE NULL',
    'tier_definition_sha256':'CHAR(64) NULL',
}

def guard_statements(database,prefix):
    result={}
    for name in [n for n in TABLES if TABLES[n][2]]+['traffic_rollup']:
        trigger=prefix+name+'_cold_bd'
        result[trigger]=('CREATE DEFINER=`root`@`localhost` TRIGGER '+storage.identifier(database)+'.'+storage.identifier(trigger)
            +' BEFORE DELETE ON '+storage.table(database,prefix,name)+' FOR EACH ROW BEGIN '
            +"IF COALESCE(@audit_archive_verified,0)<>1 OR SUBSTRING_INDEX(USER(),'@',1)<>'root' THEN "
            +"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='cold_archive_required_before_delete';END IF;END")
    return result

def install_namespace(db,database,prefix):
    storage.validate(database,(prefix,));meta=storage.table(database,'','audit_schema');guards=guard_statements(database,prefix)
    fingerprint=hashlib.sha256(''.join(guards.values()).encode()).hexdigest()
    with db.cursor() as c:
        c.execute('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',(database,'audit_schema'))
        columns={r[0] for r in c.fetchall()};missing=[name for name in POLICY_COLUMNS if name not in columns]
        if missing:c.execute('ALTER TABLE '+meta+' '+','.join('ADD COLUMN '+storage.identifier(n)+' '+POLICY_COLUMNS[n] for n in missing))
        c.execute('SELECT version,ready,tier_definition_sha256 FROM '+meta+' WHERE namespace=%s',(prefix,));state=c.fetchone()
        if not state or state[:2]!=(2,1):raise ValueError('base_schema_not_ready')
        if state[2] and state[2]!=fingerprint:raise ValueError('tier_definition_changed')
        c.execute('SELECT TRIGGER_NAME,ACTION_STATEMENT,DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s AND TRIGGER_NAME IN ('+','.join('%s' for _ in guards)+')',(database,*guards))
        existing=c.fetchall()
        for name,body,definer in existing:
            expected=guards[name].split(' FOR EACH ROW ',1)[1]
            if re.sub(r'\s+',' ',body).strip()!=re.sub(r'\s+',' ',expected).strip() or definer!='root@localhost':raise ValueError('existing_tier_guard_changed')
        seen={r[0] for r in existing}
        for name,ddl in guards.items():
            if name not in seen:c.execute(ddl)
        c.execute('UPDATE '+meta+' SET archive_policy_version=%s,hot_days=%s,online_days=%s,tier_updated_at=%s,tier_definition_sha256=%s WHERE namespace=%s',
                  (POLICY_VERSION,HOT_DAYS,ONLINE_DAYS,time.time(),fingerprint,prefix))
    db.commit();return {'namespace':prefix,'policy_version':POLICY_VERSION,'hot_days':HOT_DAYS,'online_days':ONLINE_DAYS,'guards':len(guards)}

def hot_projection(ddl,database,prefixes,name):
    primary={'审计明细':('connection_state','last_seen'),'访问记录':('visits','ts'),'入口流量汇总':('wire_samples','bucket')}.get(name)
    if not primary:return ddl
    logical,stamp=primary
    for prefix in prefixes:
        physical=storage.table(database,prefix,logical)
        pattern=r'\b(FROM|JOIN)\s+(?:`'+re.escape(database)+r'`\.)?`'+re.escape(prefix+logical)+r'`(?![a-z0-9_])'
        original=ddl
        def replace(match):
            following=re.match(r'\s+(?:AS\s+)?(`[^`]+`|[a-z][a-z0-9_]*)',original[match.end():],re.I)
            reserved={'where','order','group','join','left','right','inner','outer','on','union','limit','having','force','use','ignore'}
            alias='' if following and following[1].strip('`').lower() not in reserved else ' '+storage.identifier(prefix+logical)
            return match[1]+' (SELECT * FROM '+physical+' WHERE '+storage.identifier(stamp)+'>=UNIX_TIMESTAMP()-'+str(HOT_DAYS*86400)+')'+alias
        ddl,count=re.subn(pattern,replace,ddl,flags=re.I)
        ddl=ddl.replace(storage.identifier(database)+'.'+storage.identifier(prefix+logical)+'.',storage.identifier(prefix+logical)+'.')
        if not count:raise ValueError('hot_projection_anchor_missing:'+name+'/'+prefix)
    return ddl
