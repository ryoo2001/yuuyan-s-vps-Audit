#!/usr/bin/env python3
"""Exercise term-b4 publisher replay against session-local tables only."""
import importlib.util
import os
import sys
import time

os.environ['TRAFFIC_CENTRAL_TABLE_PREFIX'] = 'termb4_'
os.environ['TRAFFIC_CENTRAL_PUBLISHER'] = 'term-b4'
sys.path.insert(0, '/usr/local/libexec/traffic-central-storage')
import pymysql

spec = importlib.util.spec_from_file_location('termb4_receive', '/tmp/termb4-audit-task/hk_receive.py')
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)

db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', database='hk',
                     charset='utf8mb4', autocommit=False)
try:
    with db.cursor() as c:
        for table in ('samples', 'sync_state'):
            c.execute('CREATE TEMPORARY TABLE `termb4_' + table + '` LIKE `tb1_' + table + '`')
    now = time.time()
    row = ['fixture', now, 'connection', 'entry-a1', '192.0.2.1', 'example.test', 12, 30, 'test']
    def payload(seq, data, epoch='a' * 32):
        return {'version': 1, 'publisher': 'term-b4', 'epoch': epoch, 'through': seq,
                'sent_at': time.time(), 'rows': [[seq, 'samples', data]], 'missing': 0}
    receiver.ingest(db, payload(1, row))
    receiver.ingest(db, payload(1, row))
    updated = row.copy()
    updated[6] = 20
    receiver.ingest(db, payload(3, updated))
    receiver.ingest(db, payload(2, row))
    with db.cursor() as c:
        c.execute('SELECT COUNT(*),MAX(upload_bytes),MAX(download_bytes) FROM termb4_samples')
        assert c.fetchone() == (1, 20, 30)
    try:
        receiver.ingest(db, payload(4, row, 'b' * 32))
        raise AssertionError('changed epoch accepted')
    except ValueError:
        db.rollback()
    print('PASS: temporary MySQL tables, replay, ordering and epoch isolation')
finally:
    db.close()
