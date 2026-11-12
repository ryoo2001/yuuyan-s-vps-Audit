"""Plan the additive rollup repair while retaining the existing view shape."""
from receive import ROLLUP_DDL


def monthly_view_with_rollup(definition):
    if 'traffic_rollup' in definition:
        return definition
    relation = ("(SELECT ts,source_ip,node,site,upload_bytes,download_bytes FROM samples "
                "UNION ALL SELECT latest_ts,NULLIF(source_ip,''),NULLIF(node,''),"
                "NULLIF(site,''),upload_bytes,download_bytes FROM traffic_rollup)")
    if definition.count('`samples` `s`') != 1 or ' from (' not in definition or ' where ((`s`.`ts`' not in definition:
        raise ValueError('unrecognized monthly view; review before applying')
    start = definition.index(' from (')
    where = definition.index(' where ((`s`.`ts`', start)
    candidate = definition[:start] + ' from ' + relation + ' `s`' + definition[where:]
    candidate = candidate.replace('group by `latest`.`latest_ts`,', 'group by ')
    return candidate.replace('`latest`.`latest_ts`', '(MAX(MAX(`s`.`ts`)) OVER ())')


def ensure_rollup(db):
    """Caller supplies an authorized existing admin session, never new grants."""
    with db.cursor() as cursor:
        cursor.execute('SHOW CREATE VIEW `流量汇总`')
        before = cursor.fetchone()[1]
        candidate = monthly_view_with_rollup(before)
        cursor.execute(ROLLUP_DDL)
        if candidate != before:
            cursor.execute(candidate.replace('CREATE ALGORITHM=', 'CREATE OR REPLACE ALGORITHM=', 1))
    db.commit()
    return before, candidate
