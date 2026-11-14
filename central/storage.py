"""Versioned regional storage: raw facts plus transactionally maintained totals."""
import re
from tier_policy import ONLINE_DAYS

VERSION = 2
SYSTEM_DATABASES = {'mysql', 'sys', 'information_schema', 'performance_schema'}
FRIENDLY_VIEWS = {'审计明细','流量汇总','入口流量汇总','访问记录','同步状态'}
DERIVED_TABLES = {'ip_geo'}


def identifier(value):
    if value == '_seq':
        return '`_seq`'
    if value in FRIENDLY_VIEWS:
        return '`' + value + '`'
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', value):
        raise ValueError('invalid_storage_identifier')
    return '`' + value + '`'


def validate(database, prefixes):
    identifier(database)
    if database in SYSTEM_DATABASES or not prefixes or len(set(prefixes)) != len(prefixes):
        raise ValueError('invalid_region_namespace')
    for prefix in prefixes:
        if prefix and not re.fullmatch(r'[a-z][a-z0-9_]{0,21}_', prefix):
            raise ValueError('invalid_region_namespace')


def table(database, prefix, name):
    validate(database, (prefix,))
    return identifier(database) + '.' + identifier(prefix + name)


def geo_ddl(database):
    """Create the center-only source-IP geolocation cache."""
    return ("CREATE TABLE IF NOT EXISTS " + table(database, '', 'ip_geo') + " ("
            "source_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,"
            "location VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,"
            "country VARCHAR(128) COLLATE utf8mb4_bin NOT NULL DEFAULT '',"
            "province VARCHAR(128) COLLATE utf8mb4_bin NOT NULL DEFAULT '',"
            "city VARCHAR(128) COLLATE utf8mb4_bin NOT NULL DEFAULT '',"
            "isp VARCHAR(128) COLLATE utf8mb4_bin NOT NULL DEFAULT '',"
            "lookup_status VARCHAR(32) COLLATE utf8mb4_bin NOT NULL,"
            "db_version VARCHAR(96) COLLATE utf8mb4_bin NOT NULL,"
            "updated_at DOUBLE NOT NULL,PRIMARY KEY(source_ip),"
            "KEY by_status (lookup_status),KEY by_updated (updated_at)) "
            "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")


def month_key(stamp):
    return ("TIMESTAMPDIFF(SECOND,'1970-01-01 08:00:00',DATE_FORMAT("
            "TIMESTAMPADD(SECOND,FLOOR(" + stamp + ") ,'1970-01-01 08:00:00'),"
            "'%Y-%m-01 00:00:00'))")


MONTH_START = month_key('UNIX_TIMESTAMP()')
NEXT_MONTH = ("TIMESTAMPDIFF(SECOND,'1970-01-01 08:00:00',DATE_ADD(DATE_FORMAT("
              "TIMESTAMPADD(SECOND,UNIX_TIMESTAMP(),'1970-01-01 08:00:00'),"
              "'%Y-%m-01 00:00:00'),INTERVAL 1 MONTH))")
KEYS = ('source_ip', 'node', 'site')


def normalized(name, row=''):
    return "COALESCE(NULLIF(" + (row + '.' if row else '') + identifier(name) + ",''),'未识别')"


def metadata_ddl(database):
    return ("CREATE TABLE IF NOT EXISTS " + table(database, '', 'audit_schema') + " ("
            "namespace VARCHAR(32) COLLATE utf8mb4_bin PRIMARY KEY,"
            "version INT NOT NULL,ready TINYINT NOT NULL,updated_at DOUBLE NOT NULL,definition_sha256 CHAR(64) NOT NULL) "
            "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")


def monthly_ddl(database, prefix=''):
    return ("CREATE TABLE IF NOT EXISTS " + table(database, prefix, 'traffic_monthly') + " ("
            "month_start BIGINT NOT NULL,source_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL,"
            "node VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,site VARCHAR(253) COLLATE utf8mb4_bin NOT NULL,"
            "upload_bytes DECIMAL(38,0) NOT NULL,download_bytes DECIMAL(38,0) NOT NULL,"
            "fact_rows BIGINT NOT NULL,PRIMARY KEY(month_start,source_ip,node,site)) "
            "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")


def _delta(database, prefix, row, stamp, sign):
    target = table(database, prefix, 'traffic_monthly')
    values = [month_key(row + '.' + identifier(stamp))] + [normalized(k, row) for k in KEYS]
    values += [str(sign) + '*CAST(COALESCE(' + row + '.' + k + ',0) AS DECIMAL(38,0))'
               for k in ('upload_bytes', 'download_bytes')] + [str(sign)]
    match = ['month_start=' + values[0]] + [identifier(k) + '=' + values[i+1] for i,k in enumerate(KEYS)]
    return ("IF " + row + '.' + identifier(stamp) + " IS NOT NULL THEN "
            "INSERT INTO " + target + " (month_start,source_ip,node,site,upload_bytes,download_bytes,fact_rows) VALUES ("
            + ','.join(values) + ") ON DUPLICATE KEY UPDATE "
            "upload_bytes=upload_bytes+VALUES(upload_bytes),download_bytes=download_bytes+VALUES(download_bytes),"
            "fact_rows=fact_rows+VALUES(fact_rows);"
            "DELETE FROM " + target + " WHERE " + ' AND '.join(match) + " AND fact_rows=0;END IF;")


def trigger_statements(database, prefix=''):
    """Triggers observe committed absolute-value upserts, including no-op replays."""
    statements = {}
    for name, stamp in (('samples','ts'), ('traffic_rollup','latest_ts')):
        for event, suffix in (('INSERT','ai'), ('UPDATE','au'), ('DELETE','ad')):
            trigger = prefix + name + '_monthly_' + suffix
            body = ''
            if event == 'UPDATE':
                columns = (stamp, *KEYS, 'upload_bytes', 'download_bytes')
                body += 'IF NOT (' + ' AND '.join('OLD.' + identifier(k) + ' <=> NEW.' + identifier(k) for k in columns) + ') THEN '
            if event != 'INSERT':
                body += _delta(database, prefix, 'OLD', stamp, -1)
            if event != 'DELETE':
                body += _delta(database, prefix, 'NEW', stamp, 1)
            if event == 'UPDATE':
                body += 'END IF;'
            statements[trigger] = ('CREATE DEFINER=`root`@`localhost` TRIGGER '
                + identifier(database) + '.' + identifier(trigger) + ' AFTER ' + event + ' ON '
                + table(database, prefix, name) + ' FOR EACH ROW BEGIN ' + body + ' END')
    return statements


def seed_select(database, prefix=''):
    branches = []
    for name, stamp in (('samples','ts'), ('traffic_rollup','latest_ts')):
        branches.append('SELECT ' + month_key(identifier(stamp)) + ' month_start,'
            + ','.join(normalized(k) + ' AS ' + identifier(k) for k in KEYS)
            + ',COALESCE(upload_bytes,0) upload_bytes,COALESCE(download_bytes,0) download_bytes FROM '
            + table(database,prefix,name) + ' WHERE ' + identifier(stamp) + ' IS NOT NULL')
    return ('SELECT SQL_BIG_RESULT month_start,source_ip,node,site,SUM(upload_bytes),SUM(download_bytes),COUNT(*) FROM ('
            + ' UNION ALL '.join(branches) + ') facts GROUP BY month_start,source_ip,node,site')


def totals_select(database, prefixes):
    import monthbook
    validate(database, prefixes)
    branches = []
    for prefix in prefixes:
        branches.append('SELECT source_ip,node,site,upload_bytes,download_bytes,fact_rows FROM '
            + table(database,prefix,'traffic_monthly') + ' WHERE month_start=' + MONTH_START)
        # Preserve calendar totals; suppress archived replays until correction commits.
        for name, stamp in (('samples','ts'), ('traffic_rollup','latest_ts')):
            for predicate in (identifier(stamp)+'>UNIX_TIMESTAMP()',
                              identifier(stamp)+'<='+monthbook.cursor_expressions(database,prefix,name)[1][0]+' AND '+monthbook.suppressed_sql(database,prefix,name)):
                branches.append('SELECT '+','.join(normalized(k)+' AS '+identifier(k) for k in KEYS)
                    + ',-SUM(COALESCE(upload_bytes,0)) upload_bytes,-SUM(COALESCE(download_bytes,0)) download_bytes,-COUNT(*) fact_rows FROM '
                    + table(database,prefix,name)+' WHERE '+identifier(stamp)+'>='+MONTH_START+' AND '+identifier(stamp)+'<'+NEXT_MONTH
                    +' AND ('+predicate+') GROUP BY '+','.join(normalized(k) for k in KEYS))
    branches.append('SELECT source_ip,node,site,upload_bytes,download_bytes,fact_rows FROM '
        +table(database,'','traffic_calendar')+' WHERE month_start='+MONTH_START+" AND namespace IN ("+','.join("'"+p+"'"for p in prefixes)+')')
    return ('SELECT SQL_BIG_RESULT source_ip,node,site,SUM(upload_bytes) upload_bytes,SUM(download_bytes) download_bytes,'
            'SUM(fact_rows) fact_rows FROM (' + ' UNION ALL '.join(branches)
            + ') parts GROUP BY source_ip,node,site HAVING SUM(fact_rows)>0')


def latest_select(database, prefixes):
    validate(database, prefixes)
    branches = []
    for prefix in prefixes:
        for name, stamp in (('samples','ts'), ('traffic_rollup','latest_ts')):
            branches.append('SELECT MAX(' + identifier(stamp) + ') latest_ts FROM ' + table(database,prefix,name)
                + ' WHERE ' + identifier(stamp) + '>=' + MONTH_START + ' AND ' + identifier(stamp) + '<=UNIX_TIMESTAMP()')
    branches.append('SELECT MAX(latest_ts) latest_ts FROM '+table(database,'','traffic_calendar')+' WHERE month_start='+MONTH_START+' AND latest_ts<=UNIX_TIMESTAMP()'+" AND namespace IN ("+','.join("'"+p+"'"for p in prefixes)+')')
    return 'SELECT MAX(latest_ts) latest_ts FROM (' + ' UNION ALL '.join(branches) + ') stamps'


def summary_select(database, prefixes):
    total = '(s.upload_bytes+s.download_bytes)'
    return ("SELECT CONCAT(DATE_FORMAT(TIMESTAMPADD(SECOND,"+MONTH_START+",'1970-01-01 08:00:00'),'%Y/%m/%d'),"
            "'–',DATE_FORMAT(TIMESTAMPADD(SECOND,latest.latest_ts,'1970-01-01 08:00:00'),'%Y/%m/%d')) AS `时间`,"
            "s.source_ip AS `源 IP`,CASE WHEN s.source_ip='未识别' THEN '未识别' ELSE "
            "COALESCE(NULLIF(g.location,''),'未查询') END AS `IP归属地`,"
            "s.node AS `入口机器`,s.site AS `目标网站`,CASE WHEN " + total + ">=1000000000 THEN "
            "CONCAT(CAST(ROUND(" + total + "/1000000000,2) AS DECIMAL(22,2)),' GB') ELSE "
            "CONCAT(CAST(ROUND(" + total + "/1000000,2) AS DECIMAL(22,2)),' MB') END AS `流量统计` FROM ("
            + totals_select(database,prefixes) + ') s CROSS JOIN (' + latest_select(database,prefixes)
            + ') latest LEFT JOIN ' + table(database,'','ip_geo') + ' g ON g.source_ip=s.source_ip ORDER BY ' + total + ' DESC,s.source_ip,s.node,s.site')


def summary_ddl(database, prefixes):
    return ('CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW '
            + identifier(database) + '.`流量汇总` AS ' + summary_select(database,prefixes))


QUERY_INDEXES = {
    'samples': {'by_source_time': ('source_ip','ts'), 'by_site_time': ('site','ts')},
    'visits': {'by_source_time': ('source_ip','ts'), 'by_site_time': ('site','ts')},
    'connection_state': {'by_source_time': ('source_ip','last_seen'), 'by_site_time': ('site','last_seen')},
    'traffic_rollup': {'by_latest': ('latest_ts',)},
}
