"""Summary windows that reach past the 48 h raw tier read incremental hourly totals.

The part of a window at or after the boundary is read from raw rows exactly as
before. The part before it is read from traffic_hourly and widened to whole
hours. A window entirely inside the raw tier behaves exactly as it always has.
"""
import math

from tier_policy import RAW_HOT_HOURS

UNKNOWN = '未识别'


def boundary(now):
    """First instant the raw tables are guaranteed to still hold (archive cutoff is now-48 h)."""
    return int(math.ceil((now - RAW_HOT_HOURS * 3600) / 3600) * 3600)


def plan(start, end, now):
    edge = boundary(now)
    hourly = None
    if start < edge:
        hourly = (int(start // 3600 * 3600), min(edge, int(math.ceil(end / 3600) * 3600)))
    raw = (max(start, edge), end) if end > edge else None
    return raw, hourly, edge


def summary(c, column, filters, start, end, now, limit, samples='samples', visits='visits', hourly='traffic_hourly'):
    """Return (totals, rows, groups, tier, warnings). `filters` maps source_ip/site to a value or None."""
    raw, hours, edge = plan(start, end, now)
    parts, params, warnings = [], [], []
    totals = {'connections': 0, 'upload_bytes': 0, 'download_bytes': 0, 'total_bytes': 0, 'request_events': 0}
    key = "COALESCE(NULLIF(`" + column + "`,''),'unknown')"
    if raw:
        where, wp = 'ts>=%s AND ts<%s', [raw[0], raw[1]]
        for name, value in filters.items():
            if value is not None: where += ' AND `' + name + '`=%s'; wp.append(value)
        c.execute('SELECT COUNT(DISTINCT connection_id),COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM '
                  + samples + ' WHERE ' + where, wp)
        n, up, down = c.fetchone()
        c.execute('SELECT COUNT(*) FROM ' + visits + ' WHERE ' + where, wp)
        events = c.fetchone()[0]
        for k, v in (('connections', n), ('upload_bytes', up), ('download_bytes', down), ('request_events', events)):
            totals[k] += int(v)
        parts.append('SELECT ' + key + ' k,COUNT(DISTINCT connection_id) connections,SUM(upload_bytes) up,SUM(download_bytes) down,0 events FROM '
                     + samples + ' WHERE ' + where + ' GROUP BY 1')
        parts.append('SELECT ' + key + ' k,0 connections,0 up,0 down,COUNT(*) events FROM ' + visits + ' WHERE ' + where + ' GROUP BY 1')
        params += wp + wp
    if hours:
        hkey = "CASE WHEN `" + column + "`='" + UNKNOWN + "' THEN 'unknown' ELSE `" + column + "` END"
        where, hp = 'hour_start>=%s AND hour_start<%s', [hours[0], hours[1]]
        for name, value in filters.items():
            if value is not None: where += ' AND `' + name + '`=%s'; hp.append(value)
        c.execute('SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),COALESCE(SUM(visit_events),0) FROM '
                  + hourly + ' WHERE ' + where, hp)
        up, down, events = c.fetchone()
        totals['upload_bytes'] += int(up); totals['download_bytes'] += int(down); totals['request_events'] += int(events)
        parts.append('SELECT ' + hkey + ' k,0 connections,SUM(upload_bytes) up,SUM(download_bytes) down,SUM(visit_events) events FROM '
                     + hourly + ' WHERE ' + where + ' GROUP BY 1')
        params += hp
        c.execute('SELECT MIN(hour_start) FROM ' + hourly)
        first = c.fetchone()[0]
        if first is None or hours[0] < first:
            warnings.append('hourly_totals_not_available_before:' + str(int(first) if first is not None else edge))
        warnings.append('window_before_48h_rounded_to_whole_hours')
        warnings.append('connections_counted_for_raw_48h_part_only')
    totals['total_bytes'] = totals['upload_bytes'] + totals['download_bytes']
    union = ' UNION ALL '.join(parts)
    c.execute('SELECT COUNT(DISTINCT k) FROM (' + union + ') x', params)
    groups = c.fetchone()[0]
    c.execute('SELECT k,SUM(connections),SUM(up),SUM(down),SUM(events) FROM (' + union
              + ') x GROUP BY k ORDER BY SUM(up)+SUM(down) DESC,k LIMIT %s', params + [limit])
    rows = [{'key': r[0], 'connections': int(r[1]), 'upload_bytes': int(r[2]), 'download_bytes': int(r[3]),
             'total_bytes': int(r[2]) + int(r[3]), 'request_events': int(r[4])} for r in c.fetchall()]
    tier = {'boundary': edge, 'precision': 'hour' if hours else 'second',
            'raw': {'from': raw[0], 'to': raw[1]} if raw else None,
            'hourly': {'from': hours[0], 'to': hours[1]} if hours else None}
    return totals, rows, groups, tier, warnings
