#!/usr/bin/env python3
"""Bounded read-only MySQL queries; fixed database and audited CLI contract."""
import heapq,json,os,sys,time,math
from datetime import datetime,timezone,timedelta
os.environ.setdefault("TRAFFIC_CENTRAL_CONFIG", "/etc/traffic-central/reader.json")

from source_query import (parse_args,parse_iso,DETAIL_COLUMNS,BYTE_BASIS,DETAIL_DEDUP_WINDOW_SECONDS,
                          DETAIL_DEDUP_BASIS,SUMMARY_VIEW_COLUMNS,SUMMARY_VIEW_SCOPE,
                          SUMMARY_VIEW_GROUPING,SUMMARY_VIEW_TIME_BASIS,QueryError,SUMMARY_WARNINGS)
import history_cache
from receive import connect

# Allow the 30-second upload interval plus two missed cycles of grace.
# Source-side collector freshness checks remain unchanged.
SYNC_STALE_SECONDS = 90
CENTRAL_NODE = os.environ.get('TRAFFIC_CENTRAL_NODE', 'legacy-center')
PUBLISHERS = tuple(x for x in os.environ.get(
    'TRAFFIC_CENTRAL_PUBLISHERS', os.environ.get('TRAFFIC_CENTRAL_PUBLISHER', 'term-a1')).split(',') if x)
ACTIVE_EDGE_NODES = tuple(x for x in os.environ.get(
    'TRAFFIC_CENTRAL_ACTIVE_EDGE_NODES', 'entry-a1,entry-a2,entry-a3,entry-a4').split(',') if x)

DETAIL_BATCH_SIZE = 500
# Retired publishers keep their sync_state history but must not hide new faults
# behind a permanent degraded status; they are still listed in health metrics.
RETIRED_PUBLISHERS = tuple(x for x in os.environ.get('TRAFFIC_CENTRAL_RETIRED_PUBLISHERS', '').split(',') if x)


from tier_policy import HOT_DAYS, ONLINE_DAYS, RAW_HOT_HOURS, metadata as tier_metadata
import tier_summary
SUMMARY_VIEW_SCOPE='current_beijing_calendar_month_to_latest'
SUMMARY_VIEW_TIME_BASIS='beijing_month_start_to_latest_sample_date'

def _detail_key(row):
    connection_id,last_seen,source_peer,inbound_port,site,source_ip,node = row[:7]
    invalid = (connection_id is None or not source_ip or not site or str(site).lower() == 'unknown'
               or not node or inbound_port is None or last_seen is None)
    identity = connection_id if invalid else source_ip
    route_node = connection_id if not node else node
    bucket = connection_id if last_seen is None else math.floor(last_seen / 60)
    return identity,site,route_node,inbound_port,bucket


def _detail_display(row):
    (connection_id,last_seen,source_peer,inbound_port,site,source_ip,node,
     route_node,tunnel_ip,location) = row
    source = source_ip or '未识别'
    if source_peer == '172.30.3.3' and not node:
        tunnel = '172.30.3.3（云厂入口：203.0.113.103）'
    elif not node:
        if route_node is None:
            tunnel = '未识别'
        elif tunnel_ip is None:
            tunnel = f'直连（{route_node}；未经过隧道）'
        else:
            tunnel = f'{tunnel_ip}（{route_node}）'
    elif route_node is None:
        tunnel = f'未核验（{node}）'
    elif tunnel_ip is None:
        tunnel = f'直连（{node}；未经过隧道）'
    else:
        tunnel = f'{tunnel_ip}（{node}）'
    stamp = datetime.fromtimestamp(float(last_seen), timezone.utc) + timedelta(hours=8)
    if not source_ip:
        location = '未识别'
    elif not location:
        location = '未查询'
    return [stamp.strftime('%Y/%m/%d %H:%M'), source, location, tunnel, site or '']


_shared_parse_args = parse_args


def parse_args(argv):
    # details --from/--to is central-only; the shared collector parser stays unchanged.
    argv, window = history_cache.split_window(list(argv), parse_iso, QueryError)
    args = _shared_parse_args(argv)
    args.window = window
    return args


def _history_rows(cursor, database, chunks, args, lo, hi):
    """Cold rows in the region-a row shape, with current routes and locations attached."""
    cursor.execute('SELECT node,inbound_port,tunnel_ip FROM entry_routes')
    routes = cursor.fetchall()
    by_port = {}
    by_tunnel = {}
    for route in routes:
        by_port.setdefault((route[0], route[1]), route)
        by_tunnel.setdefault(route[2], route)
    places = {}
    for _, cid, seen, peer, port, site, ip, node in history_cache.rows(
            database, chunks, lo, hi, args.source_ip, args.domain):
        route = by_port.get((node, port)) or (by_tunnel.get(peer) if not node else None)
        if ip and ip not in places:
            cursor.execute('SELECT location FROM ip_geo WHERE source_ip=%s', (ip,))
            found = cursor.fetchone()
            places[ip] = found[0] if found else None
        yield (cid, seen, peer, port, site, ip, node, route[0] if route else None,
               route[2] if route else None, places.get(ip))


def _raw_rows(cursor, sql, params, first):
    batch, offset = first, 0
    while True:
        yield from batch
        if len(batch) < DETAIL_BATCH_SIZE:
            return
        offset += DETAIL_BATCH_SIZE
        cursor.execute(sql, params + [DETAIL_BATCH_SIZE, offset])
        batch = cursor.fetchall()


def _read_details(cursor, args):
    now = time.time()
    window = getattr(args, 'window', None)
    lo, hi = window if window else (now-RAW_HOT_HOURS*3600, None)
    where, params = ['c.last_seen>=%s'], [lo]
    if hi is not None:
        where.append('c.last_seen<%s')
        params.append(hi)
    for column, value in (('c.source_ip', args.source_ip), ('c.site', args.domain)):
        if value is not None:
            where.append(column + '=%s')
            params.append(value)
    sql = ('SELECT c.connection_id,c.last_seen,c.source_peer,c.inbound_port,c.site,c.source_ip,c.node,'
           'r.node,r.tunnel_ip,g.location '
           'FROM connection_state c '
           "LEFT JOIN entry_routes r ON (r.node=c.node AND r.inbound_port=c.inbound_port) OR (COALESCE(c.node,'')='' AND r.tunnel_ip=c.source_peer) "
           'LEFT JOIN ip_geo g ON g.source_ip=c.source_ip')
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY c.last_seen DESC,c.connection_id LIMIT %s OFFSET %s'
    selected, seen, ids, history = [], set(), set(), None
    try:
        cursor.execute(sql, params + [DETAIL_BATCH_SIZE, 0])
    except Exception as exc:
        # Older center grants expose only the five public views. Keep that
        # contract working while newer grants can use the indexed tables.
        message = str(exc).lower()
        code = exc.args[0] if getattr(exc, 'args', ()) else None
        if not window and (code == 1142 or 'command denied' in message or 'permission' in message):
            where, view_params = [], []
            for column, value in (('`源 IP`', args.source_ip), ('`目标网站`', args.domain)):
                if value is not None:
                    where.append(column + '=%s')
                    view_params.append(value)
            view_sql = 'SELECT * FROM `审计明细`'
            if where:
                view_sql += ' WHERE ' + ' AND '.join(where)
            cursor.execute(view_sql + ' LIMIT %s', view_params + [args.limit + 1])
            return cursor.fetchall(), None
        raise
    streams = [_raw_rows(cursor, sql, params, cursor.fetchall())]
    if window and lo < now-RAW_HOT_HOURS*3600:
        # Rows archived before this snapshot are in listed chunks; the rest are still raw.
        chunks, first = history_cache.snapshot(cursor, lo, hi)
        cursor.execute('SELECT DATABASE()')
        database = cursor.fetchone()[0]
        history = {'first_archived_day': first, 'days': [], 'chunks': 0, 'fetched_chunks': 0,
                   'fetched_bytes': 0, 'fetch_seconds': 0, 'source_tier': 'none'}
        if chunks:
            try:
                history.update(history_cache.load(database, chunks))
                streams.append(_history_rows(cursor, database, chunks, args, lo, hi))
            except history_cache.HistoryError as exc:
                history.update(source_tier='unavailable', error=str(exc))
            finally:
                history_cache.evict()
    for row in heapq.merge(*streams, key=lambda r: (-r[1], r[0])):
        if row[0] in ids:
            continue  # a connection re-archived after an update: keep its latest copy
        ids.add(row[0])
        key = _detail_key(row)
        if key in seen:
            continue
        seen.add(key)
        selected.append(_detail_display(row))
        if len(selected) > args.limit:
            break
    return selected, history


def counts(row):
    connections,up,down,events=row
    return {'connections':int(connections),'upload_bytes':int(up),'download_bytes':int(down),
            'total_bytes':int(up)+int(down),'request_events':int(events)}

def run(args):
    now=time.time()
    out={'schema_version':1,'mode':'central','storage':'mysql','node':CENTRAL_NODE,'status':'ok',
         'now':now,'retention_days':ONLINE_DAYS,'byte_basis':BYTE_BASIS,'warnings':list(SUMMARY_WARNINGS)}
    out['storage_tiers']=tier_metadata()
    db=connect()
    try:
        with db.cursor() as c:
            c.execute('SET SESSION TRANSACTION READ ONLY')
            c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
            c.execute('SELECT publisher,last_received,missing_rows FROM sync_state WHERE publisher IN (' + ','.join(['%s'] * len(PUBLISHERS)) + ')', PUBLISHERS)
            sync_rows={row[0]: row for row in c.fetchall()}
            syncs=[sync_rows.get(p) for p in PUBLISHERS]
            ages={p: (max(0, now-row[1]) if row else None) for p,row in zip(PUBLISHERS,syncs)}
            if any(age is None or age>SYNC_STALE_SECONDS for p,age in ages.items() if p not in RETIRED_PUBLISHERS):
                out['status']='degraded';out['warnings'].append('central_sync_stale_or_missing')
            if any(row and row[2] for row in syncs):
                out['status']='degraded';out['warnings'].append('publisher_missing_rows_observed')
            if args.command=='health':
                c.execute('SELECT node,last_received,metrics FROM peers ORDER BY node')
                peers={r[0]:{'age_seconds':max(0,now-r[1]),'metrics':json.loads(r[2])} for r in c.fetchall() if r[0] in ACTIVE_EDGE_NODES}
                if set(peers)!=set(ACTIVE_EDGE_NODES) or any(p['age_seconds']>SYNC_STALE_SECONDS for p in peers.values()):
                    out['status']='degraded';out['warnings'].append('edge_telemetry_stale_or_missing')
                out['metrics']={'sync_age_seconds':max((age for p,age in ages.items() if age is not None and p not in RETIRED_PUBLISHERS), default=None),
                                'sync_age_seconds_by_publisher':ages,
                                'missing_rows':max((row[2] for row in syncs if row), default=None),
                                'missing_rows_by_publisher':{p:(row[2] if row else None) for p,row in zip(PUBLISHERS,syncs)},
                                'publishers':list(PUBLISHERS),'retired_publishers':[p for p in PUBLISHERS if p in RETIRED_PUBLISHERS],'peers':peers}
                return out
            if args.command=='details':
                rows, history = _read_details(c, args)
                if args.window:
                    out['window']={'from':args.window[0],'to':args.window[1]}
                if history is not None:
                    out['history']=history
                    out['warnings'].append('history_details_from_cold_chunks_with_current_routes_and_locations')
                    if history['source_tier']=='unavailable':
                        out['status']='degraded';out['warnings'].append('history_details_unavailable:'+history['error'])
                    if history['first_archived_day'] is None or history['first_archived_day']>history_cache.beijing_day(args.window[0]):
                        out['warnings'].append('history_details_not_available_before:'+str(history['first_archived_day']))
                out.update(columns=list(DETAIL_COLUMNS),rows=[dict(zip(DETAIL_COLUMNS,r)) for r in rows[:args.limit]],
                           has_more=len(rows)>args.limit,timezone='Asia/Shanghai',time_basis='last_observed',
                           time_precision='minute',
                           deduplication={'enabled':True,'window_seconds':DETAIL_DEDUP_WINDOW_SECONDS,
                                          'basis':DETAIL_DEDUP_BASIS,
                                          'key':['source_ip','node','inbound_port','site'],
                                          'representative':'latest_last_seen',
                                          'unknown_policy':'unknown source/site/entry rows are not merged'})
                out['warnings'].append('时间显示到分钟；同一真实源 IP、入口和目标网站在同一分钟内只保留最新一行。')
                return out
            column={'source_ip':'source_ip','site':'site','node':'node'}[args.group_by]
            # Raw rows cover the last 48 h; older parts of the window read hourly totals.
            totals,rows,groups,tier,tier_warnings=tier_summary.summary(
                c,column,{'source_ip':args.source_ip,'site':args.domain},
                args.start.timestamp(),args.end.timestamp(),now,args.limit)
            out['warnings'].extend(tier_warnings);out['storage_window']=tier
            out.update(window={'from':getattr(args,'from'),'to':args.to},rows=rows,totals=totals,groups_total=groups,
                       group_by=args.group_by,truncated=groups>args.limit,
                       summary_view={'name':'流量汇总','columns':list(SUMMARY_VIEW_COLUMNS),
                                     'scope':SUMMARY_VIEW_SCOPE,'grouping':SUMMARY_VIEW_GROUPING,
                                     'units':'decimal_MB_GB','time_basis':SUMMARY_VIEW_TIME_BASIS,
                                     'time_format':'YYYY/MM/01–YYYY/MM/DD'})
            return out
    finally:
        db.rollback();db.close()

if __name__=='__main__':
    try:
        result=run(parse_args(sys.argv[1:]))
    except Exception as exc:
        result={'schema_version':1,'mode':'central','node':CENTRAL_NODE,'storage':'mysql','status':'error','now':time.time(),
                'retention_days':ONLINE_DAYS,'metrics':{},'warnings':['central_query_failed:'+type(exc).__name__]}
    print(json.dumps(result,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    sys.exit(1 if result['status']=='error' else 0)
