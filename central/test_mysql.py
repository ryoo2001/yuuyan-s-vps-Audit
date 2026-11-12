"""Real MySQL replay/retention tests use SESSION TEMPORARY tables only."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,'/usr/local/libexec/traffic-central')
import pymysql
from model import TABLES,upsert_sql,create_table_sql
from receive import ingest,prune
p=Path('/etc/traffic-central/root-password').read_text().strip()
db=pymysql.connect(unix_socket='/var/lib/traffic-central/run/mysqld.sock',user='root',password=p,database=json.loads(Path('/etc/traffic-central/writer.json').read_text())['database'],charset='utf8mb4')
try:
    with db.cursor() as c:
        for table in TABLES:
            c.execute(create_table_sql(table).replace('CREATE TABLE','CREATE TEMPORARY TABLE',1))
        statements=Path('/usr/local/libexec/traffic-central/views.sql').read_text().split(';')
        c.execute(statements[0].replace('CREATE TABLE','CREATE TEMPORARY TABLE',1))
        c.execute(statements[1].replace('CREATE TABLE','CREATE TEMPORARY TABLE',1))
    now=time.time()
    row=['replay-test',now,'c','edge','192.0.2.1','example.test',12,30,'test']
    def payload(seq,values):
        return {'version':1,'publisher':'term-a1','epoch':'a'*32,'through':seq,'sent_at':time.time(),'rows':[[seq,'samples',values]],'missing':0}
    ingest(db,payload(1,row));ingest(db,payload(1,row))
    with db.cursor() as c:
        c.execute('SELECT upload_bytes,download_bytes FROM samples');assert c.fetchone()==(12,30)
    newer=row.copy();newer[6]=20
    ingest(db,payload(3,newer));ingest(db,payload(2,row))
    with db.cursor() as c:
        c.execute('SELECT upload_bytes,download_bytes FROM samples');assert c.fetchone()==(20,30)
    wrong=payload(4,row);wrong['epoch']='b'*32
    try: ingest(db,wrong);raise AssertionError('epoch_reset_accepted')
    except ValueError: db.rollback()
    with db.cursor() as c:
        for key,days in [('expired',8),('within-retention',6)]:
            v=row.copy();v[0]=key;v[1]=now-days*86400;c.execute(upsert_sql('samples'),v+[5])
    db.commit();prune(db)
    with db.cursor() as c:
        c.execute('SELECT event_id FROM samples ORDER BY event_id');keys=[r[0] for r in c.fetchall()]
        assert keys==['replay-test','within-retention'],keys
        c.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM traffic_rollup')
        assert c.fetchone()==(12,30)
    print(json.dumps({'real_mysql_tests':{'replay_idempotent':True,'older_sequence_cannot_regress':True,'epoch_reset_rejected':True,'eight_day_deleted_six_day_kept':True},'production_rows_untouched':True}))
finally:db.close()
