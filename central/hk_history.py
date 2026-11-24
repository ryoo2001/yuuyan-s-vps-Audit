"""HK details for an explicit --from/--to window: raw rows plus cold day chunks.

Only used when a window is given; the default HK details path keeps reading the
`审计明细` view unchanged. Session keys and display match the view: one
representative per source namespace + source IP + entry + site + natural minute.
"""
import heapq
import math
import time
from datetime import datetime, timedelta, timezone

import history_cache

BATCH = 500
HOT_SECONDS = 48 * 3600


def detail_key(row):
    source_id, connection_id, last_seen, source_peer, inbound_port, site, source_ip, node = row[:8]
    invalid = (connection_id is None or not source_ip or not site or str(site).lower() == 'unknown'
               or not node or inbound_port is None or last_seen is None)
    identity = connection_id if invalid else source_ip
    route_node = connection_id if not node else node
    bucket = connection_id if last_seen is None else math.floor(last_seen / 60)
    return source_id, identity, site, route_node, inbound_port, bucket


def detail_display(row):
    (source_id, connection_id, last_seen, source_peer, inbound_port, site, source_ip, node,
     route_source, route_node, tunnel_ip, location) = row
    if source_peer == '172.30.3.3' and not node:
        tunnel = '172.30.3.3（云厂入口：203.0.113.103）'
    elif not node:
        tunnel = ('未识别' if route_node is None else f'直连（{route_node}；未经过隧道）' if tunnel_ip is None
                  else f'{tunnel_ip}（{route_node}）')
    elif route_node is None:
        tunnel = '未识别' if not source_ip else f'未核验（{node}）'
    elif tunnel_ip is None:
        tunnel = f'直连（{node}；未经过隧道）'
    else:
        tunnel = f'{tunnel_ip}（{node}）'
    stamp = datetime.fromtimestamp(float(last_seen), timezone.utc) + timedelta(hours=8)
    location = '未识别' if not source_ip else (location or '未查询')
    return [stamp.strftime('%Y/%m/%d %H:%M'), source_ip or '未识别', location, tunnel, site or '']


def _bare(relation, name):
    """The reader's relation() ends in its own alias; the joins below need c and r."""
    text, suffix = relation(name), ' AS `' + name + '`'
    if not text.endswith(suffix):
        raise ValueError('unexpected_hk_relation_shape')
    return text[:-len(suffix)]


def _raw(cursor, relation, args, lo, hi):
    where, params = ['c.last_seen>=%s', 'c.last_seen<%s'], [lo, hi]
    for column, value in (('c.source_ip', args.source_ip), ('c.site', args.domain)):
        if value is not None:
            where.append(column + '=%s'); params.append(value)
    sql = ('SELECT c.source_id,c.connection_id,c.last_seen,c.source_peer,c.inbound_port,c.site,c.source_ip,c.node,'
           'r.source_id,r.node,r.tunnel_ip,g.location FROM ' + _bare(relation, 'connection_state') + ' c LEFT JOIN '
           + _bare(relation, 'entry_routes') + ' r ON r.source_id=c.source_id AND ((r.node=c.node AND r.inbound_port=c.inbound_port) '
           "OR (COALESCE(c.node,'')='' AND r.tunnel_ip=c.source_peer)) LEFT JOIN `hk`.`ip_geo` g ON g.source_ip=c.source_ip "
           'WHERE ' + ' AND '.join(where) + ' ORDER BY c.last_seen DESC,c.connection_id LIMIT %s OFFSET %s')
    offset = 0
    while True:
        cursor.execute(sql, params + [BATCH, offset])
        batch = cursor.fetchall()
        yield from batch
        if len(batch) < BATCH:
            return
        offset += BATCH


def _cold(cursor, relation, chunks, args, lo, hi):
    cursor.execute('SELECT source_id,node,inbound_port,tunnel_ip FROM ' + relation('entry_routes'))
    by_port, by_tunnel = {}, {}
    for source, node, port, tunnel in cursor.fetchall():
        by_port.setdefault((source, node, port), (source, node, tunnel))
        by_tunnel.setdefault((source, tunnel), (source, node, tunnel))
    places = {}
    for source, cid, seen, peer, port, site, ip, node in history_cache.rows('hk', chunks, lo, hi, args.source_ip, args.domain):
        route = by_port.get((source, node, port)) or (by_tunnel.get((source, peer)) if not node else None)
        if ip and ip not in places:
            cursor.execute('SELECT location FROM `hk`.`ip_geo` WHERE source_ip=%s', (ip,))
            found = cursor.fetchone(); places[ip] = found[0] if found else None
        yield (source, cid, seen, peer, port, site, ip, node) + (route or (None, None, None)) + (places.get(ip),)


def read(cursor, args, relation):
    """Return (display rows up to limit+1, history metadata or None)."""
    lo, hi = args.window
    streams, history = [_raw(cursor, relation, args, lo, hi)], None
    if lo < time.time() - HOT_SECONDS:
        chunks, first = history_cache.snapshot(cursor, lo, hi)
        history = {'first_archived_day': first, 'days': [], 'chunks': 0, 'fetched_chunks': 0,
                   'fetched_bytes': 0, 'fetch_seconds': 0, 'source_tier': 'none'}
        if chunks:
            try:
                history.update(history_cache.load('hk', chunks))
                streams.append(_cold(cursor, relation, chunks, args, lo, hi))
            except history_cache.HistoryError as exc:
                history.update(source_tier='unavailable', error=str(exc))
            finally:
                history_cache.evict()
    selected, seen, ids = [], set(), set()
    for row in heapq.merge(*streams, key=lambda r: (-r[2], r[1])):
        if row[1] in ids:
            continue
        ids.add(row[1])
        key = detail_key(row)
        if key in seen:
            continue
        seen.add(key)
        selected.append(detail_display(row))
        if len(selected) > args.limit:
            break
    return selected, history


def annotate(out, history, window):
    """Shared output fields for a windowed details response."""
    out['window'] = {'from': window[0], 'to': window[1]}
    if history is None:
        return
    out['history'] = history
    out['warnings'].append('history_details_from_cold_chunks_with_current_routes_and_locations')
    if history['source_tier'] == 'unavailable':
        out['status'] = 'degraded'; out['warnings'].append('history_details_unavailable:' + history['error'])
    if history['first_archived_day'] is None or history['first_archived_day'] > history_cache.beijing_day(window[0]):
        out['warnings'].append('history_details_not_available_before:' + str(history['first_archived_day']))
