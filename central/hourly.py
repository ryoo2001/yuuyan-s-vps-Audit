"""Hourly traffic totals kept incrementally by triggers, independent of raw retention.

Archive deletes (@audit_archive_verified=1) do not subtract, so hours that have
left the database keep their totals. Ordinary deletes and absolute-value
upserts are applied as deltas. Rows older than RETAIN_DAYS are trimmed by
trim(); the table has no triggers of its own.
"""
import time

import storage

RETAIN_DAYS = 62
KEYS = storage.KEYS
TRIGGER_SUFFIX = '_hourly_'


def hour_key(expr):
    return 'FLOOR(' + expr + '/3600)*3600'


def ddl(database, prefix=''):
    return ('CREATE TABLE IF NOT EXISTS ' + storage.table(database, prefix, 'traffic_hourly') + ' ('
            'hour_start BIGINT NOT NULL,source_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,'
            'node VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,site VARCHAR(253) COLLATE utf8mb4_bin NOT NULL,'
            'upload_bytes DECIMAL(38,0) NOT NULL DEFAULT 0,download_bytes DECIMAL(38,0) NOT NULL DEFAULT 0,'
            'fact_rows BIGINT NOT NULL DEFAULT 0,visit_events BIGINT NOT NULL DEFAULT 0,'
            'PRIMARY KEY(hour_start,source_ip,node,site),KEY by_source(source_ip,hour_start),'
            'KEY by_site(site,hour_start)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin')


def _delta(database, prefix, row, kind, sign):
    target = storage.table(database, prefix, 'traffic_hourly')
    hour = hour_key(row + '.`ts`')
    keys = [storage.normalized(k, row) for k in KEYS]
    if kind == 'samples':
        up = str(sign) + '*CAST(COALESCE(' + row + '.upload_bytes,0) AS DECIMAL(38,0))'
        down = str(sign) + '*CAST(COALESCE(' + row + '.download_bytes,0) AS DECIMAL(38,0))'
        facts, visits = str(sign), '0'
    else:
        up, down, facts, visits = '0', '0', '0', str(sign)
    match = ['hour_start=' + hour] + [storage.identifier(k) + '=' + keys[i] for i, k in enumerate(KEYS)]
    return ('IF ' + row + '.`ts` IS NOT NULL THEN INSERT INTO ' + target
            + ' (hour_start,source_ip,node,site,upload_bytes,download_bytes,fact_rows,visit_events) VALUES ('
            + ','.join([hour] + keys + [up, down, facts, visits]) + ') ON DUPLICATE KEY UPDATE '
            'upload_bytes=upload_bytes+VALUES(upload_bytes),download_bytes=download_bytes+VALUES(download_bytes),'
            'fact_rows=fact_rows+VALUES(fact_rows),visit_events=visit_events+VALUES(visit_events);'
            'DELETE FROM ' + target + ' WHERE ' + ' AND '.join(match)
            + ' AND fact_rows=0 AND visit_events=0;END IF;')


def trigger_statements(database, prefix=''):
    statements = {}
    for kind, watched in (('samples', ('ts', *KEYS, 'upload_bytes', 'download_bytes')),
                          ('visits', ('ts', *KEYS))):
        for event, suffix in (('INSERT', 'ai'), ('UPDATE', 'au'), ('DELETE', 'ad')):
            name = prefix + kind + TRIGGER_SUFFIX + suffix
            body = ''
            if event == 'UPDATE':
                body += ('IF NOT (' + ' AND '.join('OLD.' + storage.identifier(c) + ' <=> NEW.'
                         + storage.identifier(c) for c in watched) + ') THEN ')
            if event == 'DELETE':
                body += 'IF COALESCE(@audit_archive_verified,0)<>1 THEN '
            if event != 'INSERT':
                body += _delta(database, prefix, 'OLD', kind, -1)
            if event != 'DELETE':
                body += _delta(database, prefix, 'NEW', kind, 1)
            if event != 'INSERT':
                body += 'END IF;'
            statements[name] = ('CREATE DEFINER=`root`@`localhost` TRIGGER ' + storage.identifier(database)
                                + '.' + storage.identifier(name) + ' AFTER ' + event + ' ON '
                                + storage.table(database, prefix, kind) + ' FOR EACH ROW BEGIN ' + body + ' END')
    return statements


def _bounds(column, lo, hi):
    """Half-open [lo, hi) filter; bounds are generated hour-aligned integers."""
    return ((' AND ' + column + '>=' + str(int(lo)) if lo is not None else '')
            + (' AND ' + column + '<' + str(int(hi)) if hi is not None else ''))


def seed_select(database, prefix='', lo=None, hi=None):
    """Recompute hourly totals from the raw rows still in the database."""
    keys = ','.join(storage.normalized(k) + ' AS ' + storage.identifier(k) for k in KEYS)
    where = ' WHERE `ts` IS NOT NULL' + _bounds('`ts`', lo, hi)
    samples = ('SELECT ' + hour_key('`ts`') + ' hour_start,' + keys
               + ',COALESCE(upload_bytes,0) up,COALESCE(download_bytes,0) down,1 facts,0 visits FROM '
               + storage.table(database, prefix, 'samples') + where)
    visits = ('SELECT ' + hour_key('`ts`') + ' hour_start,' + keys + ',0 up,0 down,0 facts,1 visits FROM '
              + storage.table(database, prefix, 'visits') + where)
    return ('SELECT SQL_BIG_RESULT hour_start,source_ip,node,site,SUM(up),SUM(down),SUM(facts),SUM(visits) FROM ('
            + samples + ' UNION ALL ' + visits + ') f GROUP BY hour_start,source_ip,node,site')


def _seed_chunk(db, database, prefix, lo, hi):
    """Replace [lo, hi) with a recomputation while writers to both fact tables wait.

    With the triggers already live, hours seeded earlier stay exact through
    deltas; an hour not yet seeded may hold partial deltas, which this
    overwrites with the full state under the same lock.
    """
    target = storage.table(database, prefix, 'traffic_hourly')
    started = time.monotonic()
    db.autocommit(False)
    try:
        with db.cursor() as c:
            c.execute('LOCK TABLES ' + ','.join(storage.table(database, prefix, n) + ' WRITE'
                                                for n in ('samples', 'visits', 'traffic_hourly')))
            c.execute('DELETE FROM ' + target + ' WHERE 1' + _bounds('hour_start', lo, hi))
            c.execute('INSERT INTO ' + target + ' (hour_start,source_ip,node,site,upload_bytes,download_bytes,'
                      'fact_rows,visit_events) ' + seed_select(database, prefix, lo, hi))
            groups = c.rowcount
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        with db.cursor() as c:
            c.execute('UNLOCK TABLES')
        db.autocommit(True)
    return groups, time.monotonic() - started


def seed(db, database, prefix='', start=None, chunk=86400):
    """Seed oldest first so the archive cutoff, which only advances, never overtakes an unseeded hour."""
    with db.cursor() as c:
        c.execute('SELECT MIN(m) FROM (SELECT MIN(`ts`) m FROM ' + storage.table(database, prefix, 'samples')
                  + ' UNION ALL SELECT MIN(`ts`) FROM ' + storage.table(database, prefix, 'visits') + ') x')
        first = c.fetchone()[0]
    lo = int(first // 3600 * 3600) if first is not None else int(time.time() // 3600 * 3600)
    if start is not None:
        lo = max(lo, int(start) // 3600 * 3600)
    edge = int(time.time() // 3600 * 3600)
    groups = 0; longest = 0.0; chunks = 0
    while True:
        hi = lo + chunk if lo + chunk <= edge else None
        try:
            n, seconds = _seed_chunk(db, database, prefix, lo, hi)
        except Exception as exc:
            raise ValueError('hourly_seed_incomplete:resume_from=' + str(lo) + ':' + type(exc).__name__) from exc
        groups += n; longest = max(longest, seconds); chunks += 1
        if hi is None:
            return {'groups_seeded': groups, 'chunks': chunks, 'longest_write_gate_seconds': round(longest, 4)}
        lo = hi


def install(db, database, prefix='', resume_from=None, chunk=86400):
    """Create the table and triggers, then seed in short locked chunks.

    Refuses to reseed a populated table: hours already archived out of the raw
    tables would be lost. After a failed chunk, resume_from continues from the
    hour it reports; earlier chunks are kept exact by the triggers.
    """
    storage.validate(database, (prefix,))
    target = storage.table(database, prefix, 'traffic_hourly')
    statements = trigger_statements(database, prefix)
    if resume_from is not None:
        with db.cursor() as c:
            c.execute('SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s '
                      'AND EVENT_OBJECT_TABLE IN (%s,%s) AND TRIGGER_NAME IN (' + ','.join(['%s'] * len(statements))
                      + ')', (database, prefix + 'samples', prefix + 'visits', *statements))
            if c.fetchone()[0] != len(statements):
                raise ValueError('resume_requires_installed_triggers')
        return {'namespace': prefix, 'already_installed': False, 'resumed_from': int(resume_from),
                **seed(db, database, prefix, start=resume_from, chunk=chunk)}
    with db.cursor() as c:
        c.execute(ddl(database, prefix))
        # Match by owning table, not a LIKE pattern: '' would also match other_ namespaces.
        c.execute('SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s '
                  'AND EVENT_OBJECT_TABLE IN (%s,%s)', (database, prefix + 'samples', prefix + 'visits'))
        existing = {r[0] for r in c.fetchall() if TRIGGER_SUFFIX in r[0]}
        if existing - set(statements):
            raise ValueError('unexpected_hourly_trigger')
        if existing == set(statements):
            return {'namespace': prefix, 'already_installed': True}
        c.execute('SELECT COUNT(*) FROM ' + target)
        if c.fetchone()[0]:
            raise ValueError('hourly_table_not_empty_refusing_reseed')
        for name, statement in statements.items():
            if name not in existing:
                c.execute(statement)
    return {'namespace': prefix, 'already_installed': False, **seed(db, database, prefix, chunk=chunk)}


def verify(db, database, prefix='', since=None):
    """Hours still fully in the raw tables must equal a fresh recomputation."""
    since = int(time.time() // 3600 * 3600 - 24 * 3600) if since is None else int(since)
    order = ' ORDER BY hour_start,source_ip,node,site'
    with db.cursor() as c:
        # One snapshot for both reads; trigger deltas commit with their fact rows.
        c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
        try:
            c.execute('SELECT hour_start,source_ip,node,site,upload_bytes,download_bytes,fact_rows,visit_events FROM '
                      + storage.table(database, prefix, 'traffic_hourly') + ' WHERE hour_start>=%s' + order, (since,))
            actual = c.fetchall()
            c.execute('SELECT * FROM (' + seed_select(database, prefix) + ') s WHERE hour_start>=%s' + order, (since,))
            expected = c.fetchall()
        finally:
            c.execute('COMMIT')
    if actual != expected:
        raise ValueError('hourly_totals_mismatch:' + database + '/' + prefix)
    return {'namespace': prefix, 'since': since, 'groups': len(actual), 'identical': True}


def trim(db, database, prefix='', now=None, batch=5000):
    now = time.time() if now is None else now
    cutoff = int(now // 3600 * 3600 - RETAIN_DAYS * 86400)
    removed = 0
    with db.cursor() as c:
        while True:
            c.execute('DELETE FROM ' + storage.table(database, prefix, 'traffic_hourly')
                      + ' WHERE hour_start<%s LIMIT %s', (cutoff, batch))
            removed += c.rowcount
            db.commit()
            if c.rowcount < batch:
                return {'namespace': prefix, 'cutoff': cutoff, 'removed': removed}


def main():
    import argparse
    import json
    import pymysql
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('install', 'verify', 'trim'))
    parser.add_argument('--database', required=True)
    parser.add_argument('--namespace', action='append', required=True, help='default or a short namespace, e.g. tb3')
    parser.add_argument('--since', type=int, help='verify: first hour_start to compare (default: last 24 h)')
    parser.add_argument('--resume-from', type=int, help='install: continue a failed seed from this hour_start')
    args = parser.parse_args()
    prefixes = tuple('' if p == 'default' else p + '_' for p in args.namespace)
    storage.validate(args.database, prefixes)
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', charset='utf8mb4',
                         autocommit=True, read_timeout=90)
    try:
        with db.cursor() as c:
            c.execute('SET SESSION lock_wait_timeout=4')
            c.execute('SET SESSION innodb_lock_wait_timeout=4')
            c.execute('SET SESSION max_statement_time=60')
        for prefix in prefixes:
            if args.command == 'install':
                out = install(db, args.database, prefix, resume_from=args.resume_from)
            elif args.command == 'verify':
                out = verify(db, args.database, prefix, since=args.since)
            else:
                out = trim(db, args.database, prefix)
            print(json.dumps({'database': args.database, **out}), flush=True)
    finally:
        db.close()


if __name__ == '__main__':
    main()
