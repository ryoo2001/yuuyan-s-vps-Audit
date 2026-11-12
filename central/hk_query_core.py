#!/usr/bin/env python3
"""Bounded read-only MySQL queries; fixed database and audited CLI contract."""
import json,os,sys,time,math
from datetime import datetime,timezone,timedelta
os.environ.setdefault("TRAFFIC_CENTRAL_CONFIG", "/etc/traffic-central/mcp.json")

from source_query import (parse_args,DETAIL_COLUMNS,BYTE_BASIS,DETAIL_DEDUP_WINDOW_SECONDS,
                          DETAIL_DEDUP_BASIS,SUMMARY_VIEW_COLUMNS,SUMMARY_VIEW_SCOPE,
                          SUMMARY_VIEW_GROUPING,SUMMARY_VIEW_TIME_BASIS,QueryError,SUMMARY_WARNINGS)
from receive import connect

# Allow the 30-second upload interval plus two missed cycles of grace.
# Source-side collector freshness checks remain unchanged.
SYNC_STALE_SECONDS = 90
CENTRAL_NODE = os.environ.get('TRAFFIC_CENTRAL_NODE', 'center-host')
PUBLISHERS = tuple(x for x in os.environ.get(
    'TRAFFIC_CENTRAL_PUBLISHERS', os.environ.get('TRAFFIC_CENTRAL_PUBLISHER', 'term-a1')).split(',') if x)
ACTIVE_EDGE_NODES = tuple(x for x in os.environ.get(
    'TRAFFIC_CENTRAL_ACTIVE_EDGE_NODES', 'entry-a1,entry-a3,entry-a4').split(',') if x)
DETAIL_BATCH_SIZE = 500
# Retired publishers keep their sync_state history but must not hide new faults
# behind a permanent degraded status; they are still listed in health metrics.
RETIRED_PUBLISHERS = tuple(x for x in os.environ.get('TRAFFIC_CENTRAL_RETIRED_PUBLISHERS', '').split(',') if x)

from pathlib import Path
RELATIONS = json.loads(Path("/usr/local/libexec/traffic-central-hk-store/relations.json").read_text())


from tier_policy import HOT_DAYS, ONLINE_DAYS, metadata as tier_metadata
SUMMARY_VIEW_SCOPE='current_beijing_calendar_month_to_latest'
SUMMARY_VIEW_TIME_BASIS='beijing_month_start_to_latest_sample_date'

def relation(name):
    if name not in ("samples", "visits", "sync_state", "peers", "connection_state", "connection_rates", "entry_routes"):
        raise ValueError("invalid_hk_relation")
    return "(" + RELATIONS[name] + ") AS `" + name + "`"


def _detail_key(row):
    source_id,connection_id,last_seen,source_peer,inbound_port,site,source_ip,node = row[:8]
    invalid = (connection_id is None or not source_ip or not site or str(site).lower() == 'unknown'
               or not node or inbound_port is None or last_seen is None)
    identity = connection_id if invalid else source_ip
    route_node = connection_id if not node else node
    bucket = connection_id if last_seen is None else math.floor((last_seen + 2.5) / 5)
    return source_id,identity,site,route_node,inbound_port,bucket


def _format_rate(value, interval, observed_at, last_seen, source_ip):
    if not source_ip or interval != 5 or observed_at != last_seen or value is None:
        return '未采样'
    value = float(value)
    if value < 1000000:
        return f'{value / 1000:.2f} KB/s'
    return f'{value / 1000000:.2f} MB/s'


def _detail_display(row):
    (source_id,connection_id,last_seen,source_peer,inbound_port,site,source_ip,node,
     interval,observed_at,upload_bps,download_bps,route_source,route_node,tunnel_ip) = row
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
    return [stamp.strftime('%Y/%m/%d %H:%M:%S'), source, tunnel, site or '',
            _format_rate(upload_bps, interval, observed_at, last_seen, source_ip),
            _format_rate(download_bps, interval, observed_at, last_seen, source_ip)]


def _read_details(cursor, args):
    state = relation('connection_state')
    rates = relation('connection_rates')
    routes = relation('entry_routes')
    where, params = ['c.last_seen>=%s'], [time.time()-HOT_DAYS*86400]
    for column, value in (('c.source_ip', args.source_ip), ('c.site', args.domain)):
        if value is not None:
            where.append(column + '=%s')
            params.append(value)
    sql = ('SELECT c.source_id,c.connection_id,c.last_seen,c.source_peer,c.inbound_port,c.site,c.source_ip,c.node,'
           'v.interval_seconds,v.observed_at,v.upload_bps,v.download_bps,r.source_id,r.node,r.tunnel_ip '
           'FROM ' + state + ' c LEFT JOIN ' + rates + ' v '
           'ON v.source_id=c.source_id AND v.connection_id=c.connection_id LEFT JOIN ' + routes + ' r '
           'ON r.source_id=c.source_id AND ((r.node=c.node AND r.inbound_port=c.inbound_port) OR (COALESCE(c.node,'')='' AND r.tunnel_ip=c.source_peer))')
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY c.last_seen DESC,c.connection_id LIMIT %s OFFSET %s'
    selected, seen, offset = [], set(), 0
    while True:
        try:
            cursor.execute(sql, params + [DETAIL_BATCH_SIZE, offset])
        except Exception as exc:
            # Older center grants expose only the five public views. Keep that
            # contract working while newer grants can use the indexed tables.
            message = str(exc).lower()
            code = exc.args[0] if getattr(exc, 'args', ()) else None
            if offset == 0 and (code == 1142 or 'command denied' in message or 'permission' in message):
                where, view_params = [], []
                for column, value in (('`源 IP`', args.source_ip), ('`目标网站`', args.domain)):
                    if value is not None:
                        where.append(column + '=%s')
                        view_params.append(value)
                view_sql = 'SELECT * FROM `审计明细`'
                if where:
                    view_sql += ' WHERE ' + ' AND '.join(where)
                cursor.execute(view_sql + ' LIMIT %s', view_params + [args.limit + 1])
                return cursor.fetchall()
            raise
        batch = cursor.fetchall()
        for row in batch:
            key = _detail_key(row)
            if key in seen:
                continue
            seen.add(key)
            selected.append(_detail_display(row))
            if len(selected) > args.limit:
                return selected
        if len(batch) < DETAIL_BATCH_SIZE:
            return selected
        offset += DETAIL_BATCH_SIZE


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
            c.execute('SELECT publisher,last_received,missing_rows FROM ' + relation('sync_state') + ' WHERE publisher IN (' + ','.join(['%s'] * len(PUBLISHERS)) + ')', PUBLISHERS)
            sync_rows={row[0]: row for row in c.fetchall()}
            syncs=[sync_rows.get(p) for p in PUBLISHERS]
            ages={p: (max(0, now-row[1]) if row else None) for p,row in zip(PUBLISHERS,syncs)}
            if any(age is None or age>SYNC_STALE_SECONDS for p,age in ages.items() if p not in RETIRED_PUBLISHERS):
                out['status']='degraded';out['warnings'].append('central_sync_stale_or_missing')
            if any(row and row[2] for row in syncs):
                out['status']='degraded';out['warnings'].append('publisher_missing_rows_observed')
            if args.command=='health':
                c.execute('SELECT node,last_received,metrics FROM ' + relation('peers') + ' ORDER BY node')
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
                rows = _read_details(c, args)
                out.update(columns=list(DETAIL_COLUMNS),rows=[dict(zip(DETAIL_COLUMNS,r)) for r in rows[:args.limit]],
                           has_more=len(rows)>args.limit,timezone='Asia/Shanghai',time_basis='last_observed',
                           rate_basis='source_ip_five_second_sampled_payload_rate', rate_window_seconds=5, rate_scope='source_ip',
                           deduplication={'enabled':True,'window_seconds':DETAIL_DEDUP_WINDOW_SECONDS,
                                          'basis':DETAIL_DEDUP_BASIS,
                                          'key':['source_ip','node','inbound_port','site'],
                                          'representative':'latest_last_seen',
                                          'unknown_policy':'unknown source/site/entry rows are not merged'})
                out['warnings'].append('速率为同一真实源 IP 在该观测时间前 5 秒的合计均速；同一真实源 IP、入口和目标网站在 5 秒会话窗口内只保留最新一行；底层连接仍保留，窗口不足或未知源显示未采样。')
                return out
            column={'source_ip':'source_ip','site':'site','node':'node'}[args.group_by]
            key="COALESCE(NULLIF(`"+column+"`,''),'unknown')"
            where='ts>=%s AND ts<%s'
            params=[args.start.timestamp(),args.end.timestamp()]
            for name,value in [('source_ip',args.source_ip),('site',args.domain)]:
                if value is not None:where+=' AND `'+name+'`=%s';params.append(value)
            c.execute('SELECT COUNT(DISTINCT connection_id),COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),0 FROM ' + relation('samples') + ' WHERE '+where,params)
            totals=counts(c.fetchone())
            c.execute('SELECT COUNT(*) FROM ' + relation('visits') + ' WHERE '+where,params);totals['request_events']=c.fetchone()[0]
            union=('SELECT '+key+' k, COUNT(DISTINCT connection_id) connections, SUM(upload_bytes) up, SUM(download_bytes) down,0 events FROM ' + relation('samples') + ' WHERE '+where+' GROUP BY 1 UNION ALL SELECT '+key+' k,0 connections,0 up,0 down,COUNT(*) events FROM ' + relation('visits') + ' WHERE '+where+' GROUP BY 1')
            c.execute('SELECT COUNT(DISTINCT k) FROM ('+union+') x',params+params);groups=c.fetchone()[0]
            c.execute('SELECT k,SUM(connections),SUM(up),SUM(down),SUM(events) FROM ('+union+') x GROUP BY k ORDER BY SUM(up)+SUM(down) DESC,k LIMIT %s',params+params+[args.limit])
            rows=[{'key':r[0],**counts(r[1:])} for r in c.fetchall()]
            if args.start.timestamp()<now-ONLINE_DAYS*86400:out['warnings'].append('requested_window_requires_explicit_cold_archive')
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
