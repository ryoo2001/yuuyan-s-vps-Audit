"""Execution structure of the `审计明细` view: same rows, same order, bounded reads stop early.

The public contract is unchanged: one representative (latest last_seen, then
smallest connection_id) per verified source IP + entry + site + five-second
window, and unknown rows are never merged. The original definition ranks every
hot row with ROW_NUMBER() before it can return the first one. Two steps:

* `by_detail`, a covering index in display order, lets the original definition
  read the index instead of the wide rows. Applies to every namespace.
* For a single-namespace database the window is replaced by an equivalent
  anti-join over that index, so `LIMIT n` stops after n rows.
* A multi-namespace view is a UNION that must be materialised either way. It
  keeps the window but ranks and joins inside each namespace over the index.

Only a live definition that matches the reviewed shape is rewritten; anything
else is refused rather than guessed at.
"""
import re

import storage

INDEX = 'by_detail'
INDEX_COLUMNS = ('last_seen', 'connection_id', 'source_ip', 'node', 'inbound_port', 'site', 'source_peer')
COLUMNS = ['时间', '源 IP', 'IP归属地', '隧道内网 IP（入口机器）', '目标网站']
LEGACY_COLUMNS = COLUMNS + ['最近上传速率', '最近下载速率']
HOT = 'unix_timestamp() - 604800'
ORDER = "order by `c`.`last_seen` desc,`c`.`connection_id`"
WINDOW = (
    "row_number() over ( partition by case when `c`.`connection_id` is null or `c`.`source_ip` is null "
    "or `c`.`source_ip` = '' or `c`.`site` is null or `c`.`site` = '' or lcase(`c`.`site`) = 'unknown' "
    "or `c`.`node` is null or `c`.`node` = '' or `c`.`inbound_port` is null or `c`.`last_seen` is null "
    "then `c`.`connection_id` else `c`.`source_ip` end,`c`.`site`,case when `c`.`node` is null or "
    "`c`.`node` = '' then `c`.`connection_id` else `c`.`node` end,`c`.`inbound_port`,case when "
    "`c`.`last_seen` is null then `c`.`connection_id` else floor((`c`.`last_seen` + 2.5) / 5) end "
    + ORDER + ") AS `_session_rank` from (select ")
ROUTE_PLAIN = "`r`.`node` = `c`.`node` and `r`.`inbound_port` = `c`.`inbound_port`"
ROUTE_PEER = ROUTE_PLAIN + " or coalesce(`c`.`node`,'') = '' and `r`.`tunnel_ip` = `c`.`source_peer`"
# Rows the window never merges: each is its own partition.
UNMERGED = ("`c`.`source_ip` is null or `c`.`source_ip` = '' or `c`.`site` is null or `c`.`site` = '' "
            "or lcase(`c`.`site`) = 'unknown' or `c`.`node` is null or `c`.`node` = '' "
            "or `c`.`inbound_port` is null")


def display_projection(sql):
    """Project a normalized legacy definition to minute details without rate reads.

    Only the two rate expressions and their primary-key joins are removed.
    Session partitions, raw timestamps and namespace order remain in the SQL.
    """
    sql = sql.replace('%H:%i:%s', '%H:%i')
    rate = (r",case when `c`\.`source_ip` is null or `c`\.`source_ip` = '' "
            r"or `v`\.`interval_seconds` is null .*? end AS `最近(?:上传|下载)速率`")
    sql = re.sub(rate, '', sql, flags=re.IGNORECASE)
    sql = re.sub(r",`u`\.`最近(?:上传|下载)速率` AS `最近(?:上传|下载)速率`", '', sql)
    sql = re.sub(r" left join `[^`]+`\.`(?:[a-z][a-z0-9]*_)?connection_rates` `v` "
                 r"on\(`v`\.`connection_id` = `c`\.`connection_id`\)", '', sql, flags=re.IGNORECASE)
    if '最近上传速率' in sql or '最近下载速率' in sql or '`v`.' in sql or 'connection_rates`' in sql:
        raise ValueError('unexpected_detail_rate_expression')
    return sql


def index_ddl(database, prefix=''):
    # last_seen DESC, connection_id ASC is exactly the view's display order.
    columns = ','.join('`' + name + '`' + (' DESC' if name == 'last_seen' else '') for name in INDEX_COLUMNS)
    return ('ALTER TABLE ' + storage.table(database, prefix, 'connection_state') + ' ADD INDEX `' + INDEX
            + '` (' + columns + '), ALGORITHM=INPLACE, LOCK=NONE')


def ensure_index(db, database, prefix=''):
    """Create the covering index once; refuse a same-named index of another shape."""
    storage.validate(database, (prefix,))
    with db.cursor() as c:
        c.execute('SELECT COLUMN_NAME,COLLATION FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s '
                  'AND TABLE_NAME=%s AND INDEX_NAME=%s ORDER BY SEQ_IN_INDEX',
                  (database, prefix + 'connection_state', INDEX))
        existing = c.fetchall()
        if existing:
            expected = [(name, 'D' if name == 'last_seen' else 'A') for name in INDEX_COLUMNS]
            if [tuple(row) for row in existing] != expected:
                raise ValueError('detail_index_definition_changed')
            return False
        c.execute(index_ddl(database, prefix))
    return True


def parse_single(definition, database):
    """Return (select list, route join condition) of a reviewed one-namespace view."""
    text, name = definition.strip(), storage.identifier(database)
    head, found, _ = text.partition(' from (')
    if not found or '_session_rank' in head or re.findall(r' AS `([^`]+)`', head) not in (COLUMNS, LEGACY_COLUMNS):
        raise ValueError('unexpected_detail_view_columns')
    source = (' from ' + name + '.`connection_state` where ' + name + '.`connection_state`.`last_seen` >= ' + HOT
              + ') `c`) `c` left join ' + name + '.`connection_rates` `v` on(`v`.`connection_id` = `c`.`connection_id`))'
              ' left join ' + name + '.`entry_routes` `r` on(')
    if 'connection_rates`' not in text:
        # New minute projections omit rates. MariaDB may discard redundant
        # parentheses around joins while normalizing VIEW_DEFINITION.
        base = (' from ' + name + '.`connection_state` where ' + name + '.`connection_state`.`last_seen` >= ' + HOT
                + ') `c`) `c`')
        matched = re.search(re.escape(base) + r'\)* left join ' + re.escape(name + '.`entry_routes` `r` on('), text)
        if not matched:
            raise ValueError('unexpected_detail_view_shape')
        source = matched[0]
    geo = (' left join ' + name + '.`ip_geo` `g` on(`g`.`source_ip` = `c`.`source_ip`)'
           ' where `c`.`_session_rank` = 1 ' + ORDER)
    if (text.count(source) != 1 or not text.endswith(geo) or text.count(WINDOW) != 1 or text.count(HOT) != 1
            or text.count('connection_state`') != 16 or text.count('ip_geo`') != 1):
        raise ValueError('unexpected_detail_view_shape')
    route_blob = text[text.index(source) + len(source):text.index(geo)]
    if not route_blob.endswith('))'):
        raise ValueError('unexpected_detail_route_join')
    route = route_blob[:-2]
    if route not in (ROUTE_PLAIN, ROUTE_PEER):
        raise ValueError('unexpected_detail_route_join')
    return head, route


def single_select(head, database, route):
    """The anti-join form: a row is shown unless a later row of its session window exists."""
    table = lambda name: storage.table(database, '', name)
    hint = ' force index (`' + INDEX + '`)'
    latest = ('not exists (select 1 from ' + table('connection_state') + ' `d`' + hint
              + ' where `d`.`last_seen` >= `c`.`last_seen` - 5 and `d`.`last_seen` <= `c`.`last_seen` + 5'
              ' and `d`.`last_seen` >= ' + HOT
              + ' and `d`.`source_ip` = `c`.`source_ip` and `d`.`site` = `c`.`site` and `d`.`node` = `c`.`node`'
              ' and `d`.`inbound_port` = `c`.`inbound_port`'
              ' and floor((`d`.`last_seen` + 2.5) / 5) = floor((`c`.`last_seen` + 2.5) / 5)'
              ' and (`d`.`last_seen` > `c`.`last_seen` or `d`.`last_seen` = `c`.`last_seen`'
              ' and `d`.`connection_id` < `c`.`connection_id`))')
    return display_projection(head + ' from ((' + table('connection_state') + ' `c`' + hint + ' left join '
            + table('connection_rates') + ' `v` on(`v`.`connection_id` = `c`.`connection_id`)) left join '
            + table('entry_routes') + ' `r` on(' + route + ')) left join '
            + storage.table(database, '', 'ip_geo') + ' `g` on(`g`.`source_ip` = `c`.`source_ip`) where `c`.`last_seen` >= ' + HOT
            + ' and (' + UNMERGED + ' or ' + latest + ') ' + ORDER)


def parse_union(definition, database):
    """Return (select list, namespaces) of a reviewed multi-namespace view."""
    text, name = definition.strip(), storage.identifier(database)
    head, found, _ = text.partition(' from (')
    if not found or '_session_rank' in head or re.findall(r' AS `([^`]+)`', head) not in (COLUMNS, LEGACY_COLUMNS):
        raise ValueError('unexpected_detail_view_columns')
    end = (' on(`r`.`source_id` = `c`.`source_id` and (' + ROUTE_PEER + '))) left join `'
           + database + '`.`ip_geo` `g` on(`g`.`source_ip` = `c`.`source_ip`) where `c`.`_session_rank` = 1 ' + ORDER)
    window = WINDOW.replace('partition by case', 'partition by `c`.`source_id`,case', 1)
    found = {table: re.findall(' from ' + re.escape(name) + r'\.`([a-z][a-z0-9]*_)' + table + '`', text)
             for table in ('connection_state', 'connection_rates', 'entry_routes')}
    prefixes = found['connection_state']
    body = text[:-len(end)].split(' from (', 1)[1]
    if (not text.endswith(end) or text.count(window) != 1 or len(prefixes) < 2
            or len(set(prefixes)) != len(prefixes) or any(found[t] != prefixes for t in found)
            or text.count('connection_state`') != 15 * len(prefixes) or ' where ' in body.lower()):
        # A filtered, renamed or extra branch must never be flattened away silently.
        raise ValueError('unexpected_detail_view_shape')
    return head, tuple(prefixes)


def union_select(head, database, prefixes, hot=None):
    """Rank and join inside each namespace, then merge the already narrow results.

    The session window never spans namespaces (source_id is part of its key),
    so ranking per namespace is the same partitioning. Each branch reads the
    covering index and joins rates/routes by primary key instead of joining
    three five-way UNIONs. `hot` is an optional cutoff expression; without it
    the view keeps showing every online row, exactly as the definition it replaces.
    """
    storage.validate(database, tuple(prefixes))
    branches = []
    for prefix in prefixes:
        table = lambda name: storage.table(database, prefix, name)
        inner = ('select `c`.`connection_id` AS `connection_id`,`c`.`last_seen` AS `last_seen`,'
                 '`c`.`source_peer` AS `source_peer`,`c`.`inbound_port` AS `inbound_port`,`c`.`site` AS `site`,'
                 '`c`.`source_ip` AS `source_ip`,`c`.`node` AS `node`,' + WINDOW[:-len(' from (select ')]
                 + ' from ' + table('connection_state') + ' `c`'
                 + (' where `c`.`last_seen` >= ' + hot if hot else ''))
        branches.append(display_projection(head + ",`c`.`last_seen` AS `_last_seen`,concat('" + prefix[:-1]
                        + "/',`c`.`connection_id`) AS `_connection_id` from ((" + '(' + inner + ') `c` left join '
                        + table('connection_rates') + ' `v` on(`v`.`connection_id` = `c`.`connection_id`)) left join '
                        + table('entry_routes') + ' `r` on(' + ROUTE_PEER + ')) left join '
                        + storage.table(database, '', 'ip_geo') + ' `g` on(`g`.`source_ip` = `c`.`source_ip`) where `c`.`_session_rank` = 1'))
    return ('select ' + ','.join('`u`.`' + column + '` AS `' + column + '`' for column in COLUMNS) + ' from ('
            + ' union all '.join(branches) + ') `u` order by `u`.`_last_seen` desc,`u`.`_connection_id`')


def view_ddl(database, select):
    return ('CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW '
            + storage.identifier(database) + '.`审计明细` AS ' + select)


def current_definition(db, database):
    with db.cursor() as c:
        c.execute("SELECT VIEW_DEFINITION FROM information_schema.VIEWS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='审计明细'",
                  (database,))
        row = c.fetchone()
    if not row:
        raise ValueError('detail_view_missing')
    return row[0]


def install(db, database, prefixes):
    """Index every namespace; rewrite the view only for a single unprefixed namespace."""
    storage.validate(database, tuple(prefixes))
    added = [prefix for prefix in prefixes if ensure_index(db, database, prefix)]
    rewritten = False
    definition = current_definition(db, database)
    if tuple(prefixes) == ('',):
        if ' force index (`' + INDEX + '`)' not in definition:
            head, route = parse_single(definition, database)
            select = single_select(head, database, route)
            rewritten = True
    elif '`_last_seen`' not in definition:
        head, found = parse_union(definition, database)
        if set(found) != set(prefixes):
            raise ValueError('detail_view_namespaces_differ')
        select = union_select(head, database, found)
        rewritten = True
    if rewritten:
        with db.cursor() as c:
            c.execute(view_ddl(database, select))
    return {'indexes_added': added, 'view_rewritten': rewritten}
