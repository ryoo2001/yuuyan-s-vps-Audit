"""Explicit regional schema v2 installation; no account or service mutations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from model import TABLES, create_table_sql
import storage
import tiering
import monthbook
import detail_view


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def install_indexes(db, database, prefix):
    added = []
    with db.cursor() as c:
        for name, indexes in storage.QUERY_INDEXES.items():
            c.execute('SELECT INDEX_NAME,GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) '
                      'FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s GROUP BY INDEX_NAME',
                      (database, prefix+name))
            existing = dict(c.fetchall())
            for index, columns in indexes.items():
                if index in existing:
                    if existing[index] != ','.join(columns):
                        raise ValueError('index_definition_changed:'+index)
                    continue
                c.execute('ALTER TABLE ' + storage.table(database,prefix,name) + ' ADD INDEX '
                    + storage.identifier(index) + ' (' + ','.join(storage.identifier(x) for x in columns)
                    + '), ALGORITHM=INPLACE, LOCK=NONE')
                added.append(prefix+name+'.'+index)
    return added


def install_namespace(db, database, prefix, *, indexes=True):
    storage.validate(database,(prefix,))
    statements=storage.trigger_statements(database,prefix)
    fingerprint=_digest(storage.monthly_ddl(database,prefix)+''.join(statements.values()))
    meta=storage.table(database,'','audit_schema')
    target=storage.table(database,prefix,'traffic_monthly')
    with db.cursor() as c:
        c.execute(storage.metadata_ddl(database))
        c.execute('SELECT version,ready,definition_sha256 FROM '+meta+' WHERE namespace=%s',(prefix,))
        state=c.fetchone()
        c.execute('SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s',
                  (database,prefix+'traffic_monthly'))
        if c.fetchone() and state is None:raise ValueError('unregistered_monthly_table_refused')
        c.execute(storage.monthly_ddl(database,prefix))
        if state and state[2] != fingerprint:
            raise ValueError('existing_storage_definition_changed')
        c.execute("SELECT TRIGGER_NAME,ACTION_STATEMENT,DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s AND ACTION_TIMING='AFTER' AND EVENT_OBJECT_TABLE IN (%s,%s)",
                  (database,prefix+'samples',prefix+'traffic_rollup'))
        live_triggers=c.fetchall()
        existing={r[0] for r in live_triggers}
        if existing-set(statements):
            raise ValueError('unexpected_existing_trigger')
        for name,body,definer in live_triggers:
            expected=statements[name].split(' FOR EACH ROW ',1)[1]
            if re.sub(r'\s+',' ',body).strip()!=re.sub(r'\s+',' ',expected).strip() or definer!='root@localhost':
                raise ValueError('existing_trigger_definition_changed')
        if state and state[:2] == (storage.VERSION,1):
            if existing != set(statements):raise ValueError('ready_namespace_missing_trigger')
            return {'namespace':prefix,'already_ready':True,'indexes_added':install_indexes(db,database,prefix) if indexes else []}
        c.execute('INSERT INTO '+meta+' (namespace,version,ready,updated_at,definition_sha256) VALUES(%s,%s,0,%s,%s) '
                  'ON DUPLICATE KEY UPDATE ready=0,updated_at=VALUES(updated_at)',(prefix,storage.VERSION,time.time(),fingerprint))
        db.commit()
        for name,ddl in statements.items():
            if name not in existing:c.execute(ddl)
    # All six triggers are now present. Bounded locks close the installation
    # interval without stopping a publisher or rewriting any raw fact.
    started=time.monotonic()
    db.autocommit(False)
    try:
        with db.cursor() as c:
            c.execute('LOCK TABLES '+','.join(storage.table(database,prefix,n)+' WRITE'
                for n in ('samples','traffic_rollup','traffic_monthly'))+','+meta+' WRITE')
            c.execute('DELETE FROM '+target)
            c.execute('INSERT INTO '+target+' (month_start,source_ip,node,site,upload_bytes,download_bytes,fact_rows) '
                      +storage.seed_select(database,prefix))
            groups=c.rowcount
            c.execute('SELECT COUNT(*) FROM '+target+' WHERE fact_rows<=0 OR upload_bytes<0 OR download_bytes<0')
            if c.fetchone()[0]:raise ValueError('seed_totals_invalid')
            c.execute('UPDATE '+meta+' SET ready=1,updated_at=%s WHERE namespace=%s',(time.time(),prefix))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        with db.cursor() as c:c.execute('UNLOCK TABLES')
        db.autocommit(True)
    return {'namespace':prefix,'already_ready':False,'groups_seeded':groups,
            'write_gate_seconds':round(time.monotonic()-started,4),
            'indexes_added':install_indexes(db,database,prefix) if indexes else []}


def verify_namespace(db,database,prefix):
    with db.cursor() as c:
        c.execute('SELECT month_start,source_ip,node,site,upload_bytes,download_bytes,fact_rows FROM '
                  +storage.table(database,prefix,'traffic_monthly')+' ORDER BY month_start,source_ip,node,site')
        actual=c.fetchall()
        c.execute(storage.seed_select(database,prefix)+' ORDER BY month_start,source_ip,node,site')
        expected=c.fetchall()
        if actual != expected:raise ValueError('namespace_totals_mismatch:'+database+'/'+prefix)
    return {'namespace':prefix,'groups':len(actual),'all_months_identical':True}


def _relation(database,prefixes,name):
    columns=TABLES[name][0] if name in TABLES else ('publisher epoch last_seq last_received sent_at missing_rows'.split())
    parts=[]
    for prefix in prefixes:
        namespace=prefix.rstrip('_')
        expressions=[]
        for column in columns:
            expr=storage.identifier(column)
            if namespace and ((name=='peers' and column=='node') or (name=='sync_state' and column=='publisher')):
                expr="CONCAT('"+namespace+"/',"+expr+")"
            expressions.append(expr+' AS '+storage.identifier(column))
        parts.append('SELECT '+','.join(expressions)+' FROM '+storage.table(database,prefix,name))
    return ' UNION ALL '.join(parts)


def base_view_ddls(database,prefixes,text):
    """New regions get the same five public projections and source isolation."""
    storage.validate(database,prefixes)
    statements={}
    for chunk in text.split(';'):
        match=re.search(r'CREATE OR REPLACE SQL SECURITY DEFINER VIEW `([^`]+)` AS',chunk)
        if match:statements[match[1]]=chunk[match.end():].strip()
    result={}
    for name,sql in statements.items():
        if name=='流量汇总':
            result[name]=storage.summary_ddl(database,prefixes);continue
        if name=='审计明细':
            parts=[]
            for prefix in prefixes:
                branch=sql
                for raw in TABLES:
                    branch=re.sub(r'\b(FROM|JOIN) '+raw+r'\b',lambda m:m[1]+' '+storage.table(database,prefix,raw),branch)
                parts.append('SELECT * FROM ('+branch+') d'+str(len(parts)))
            query=' UNION ALL '.join(parts)+' ORDER BY `时间` DESC'
        else:
            query=sql
            for raw in (*TABLES,'sync_state'):
                query=re.sub(r'\b(FROM|JOIN) '+raw+r'\b',lambda m:m[1]+' ('+_relation(database,prefixes,raw)+') '+raw,query)
        result[name]=tiering.hot_projection('CREATE OR REPLACE SQL SECURITY DEFINER VIEW '+storage.identifier(database)+'.'+storage.identifier(name)+' AS '+query,database,prefixes,name)
    if set(result)!={'审计明细','流量汇总','入口流量汇总','访问记录','同步状态'}:raise ValueError('incomplete_base_views')
    return result


def create_region(db,database,prefixes,text):
    """Only a new, explicitly named database; no grants are inferred."""
    storage.validate(database,prefixes)
    with db.cursor() as c:
        c.execute('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(database,))
        if c.fetchone():raise ValueError('create_requires_new_database')
        c.execute('CREATE DATABASE '+storage.identifier(database)+' CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
        c.execute('USE '+storage.identifier(database))
        # The first two base statements are sync_state and traffic_rollup DDL.
        for prefix in prefixes:
            for name in TABLES:
                c.execute(create_table_sql(name).replace('`'+name+'`',storage.table(database,prefix,name),1))
            for chunk in text.split(';')[:2]:
                for name in ('sync_state','traffic_rollup'):
                    if 'CREATE TABLE IF NOT EXISTS '+name+' (' in chunk:
                        c.execute(chunk.replace('CREATE TABLE IF NOT EXISTS '+name+' (',
                            'CREATE TABLE IF NOT EXISTS '+storage.table(database,prefix,name)+' (',1))
        c.execute(storage.geo_ddl(database))
    for prefix in prefixes:
        install_namespace(db,database,prefix)
        tiering.install_namespace(db,database,prefix)
        monthbook.install(db,database,prefix)
    with db.cursor() as c:
        for ddl in base_view_ddls(database,prefixes,text).values():c.execute(ddl)
    # Covering index for the detail view on every namespace. The bounded-read view
    # form is applied only when the generated definition has the reviewed shape;
    # otherwise the window definition stays, which is slower but equally correct.
    for prefix in prefixes:detail_view.ensure_index(db,database,prefix)
    try:detail=detail_view.install(db,database,prefixes)['view_rewritten']
    except ValueError:detail=False
    return {'database':database,'schema_version':storage.VERSION,'namespaces':prefixes,'access_provisioned':False,
            'detail_view_bounded':detail}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--database',required=True)
    parser.add_argument('--namespace',action='append',default=None,help='default or a short namespace, e.g. edge')
    parser.add_argument('--create',action='store_true')
    parser.add_argument('--migrate',action='store_true')
    args=parser.parse_args()
    prefixes=tuple('' if p=='default' else p+'_' for p in (args.namespace or ['default']))
    storage.validate(args.database,prefixes)
    import pymysql
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
    try:
        with db.cursor() as c:
            c.execute('SET SESSION lock_wait_timeout=4')
            c.execute('SET SESSION innodb_lock_wait_timeout=4')
            c.execute('SET SESSION max_statement_time=20')
        if args.create and args.migrate:raise ValueError('choose_one_operation')
        if args.create:
            result=create_region(db,args.database,prefixes,Path(__file__).with_name('views.sql').read_text())
        elif args.migrate:
            result={'database':args.database,'namespaces':[install_namespace(db,args.database,p) for p in prefixes]}
        else:result={'database':args.database,'planned_namespaces':prefixes,'schema_version':storage.VERSION,'mutated':False}
        print(json.dumps(result))
    finally:db.close()


if __name__=='__main__':main()
