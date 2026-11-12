"""HK physical table namespaces and unified read-only logical views."""
import re
SOURCES = {"tb1": "hk", "tb2": "term-b2", "termc": "b-termc"}
TABLES = ("samples", "visits", "wire_samples", "connection_state", "connection_rates",
          "entry_routes", "peers", "sync_state", "traffic_rollup")
ID_COLUMNS = {"event_id", "connection_id", "flow_id"}


def append_namespace(relations, source, template="tb1"):
    """Extend normalized live relations without regenerating existing branches."""
    if set(relations) != set(TABLES) or source not in ("tb3", "termb4") or template != "tb1":
        raise ValueError("invalid_namespace_extension")
    result = {}
    for table, sql in relations.items():
        branches = re.split(r"\s+union all\s+", sql, flags=re.IGNORECASE)
        first = branches[0]
        if ("`hk`.`tb1_" + table + "`" not in first
                or "'tb1' AS `source_id`" not in first
                or "`" + source + "_" in sql or "'" + source + "'" in sql):
            raise ValueError("unexpected_namespace_relation:" + table)
        branch = first.replace("`tb1_", "`" + source + "_").replace("'tb1/", "'" + source + "/")
        branch = branch.replace("'tb1' AS `source_id`", "'" + source + "' AS `source_id`")
        result[table] = sql + " union all " + branch
    return result


def extend_inlined_view(ddl, relations, extended):
    """Replace exact live subqueries, preserving all outer display SQL."""
    if set(relations) != set(TABLES) or set(extended) != set(TABLES):
        raise ValueError("incomplete_hk_relations")
    replacements = 0
    for table in sorted(TABLES, key=lambda name: len(relations[name]), reverse=True):
        old = "(" + relations[table] + ")"
        replacements += ddl.count(old)
        ddl = ddl.replace(old, "(" + extended[table] + ")")
    if not replacements:
        raise ValueError("no_matching_live_relations")
    return ddl


def extend_normalized_view(ddl, source):
    """Append a namespace to normalized live UNIONs, retaining hot filters."""
    if source != 'termb4':
        raise ValueError('invalid_namespace_extension')
    token = re.compile(r"'(?:''|\\.|[^'\\])*'|`(?:``|[^`])*`|[A-Za-z_][A-Za-z_0-9]*|[()]|\S")
    tokens = []
    depth = 0
    for match in token.finditer(ddl):
        value = match.group()
        if value == ')':
            depth -= 1
            if depth < 0:
                raise ValueError('unbalanced_view')
        tokens.append((value, depth, match.start(), match.end()))
        if value == '(':
            depth += 1
    if depth:
        raise ValueError('unbalanced_view')
    inserts = []
    found = set()
    for i in range(len(tokens) - 2):
        value, level, _, _ = tokens[i]
        if value != "'tb1'" or tokens[i + 1][:2] != ('AS', level) or tokens[i + 2][:2] != ('`source_id`', level):
            continue
        starts = [j for j in range(i) if tokens[j][1] == level and tokens[j][0].lower() == 'select']
        if not starts:
            raise ValueError('missing_branch_select')
        start = starts[-1]
        union = next((j for j in range(i + 3, len(tokens)) if tokens[j][1] < level or
                      (tokens[j][1] == level and tokens[j][0].lower() == 'union')), None)
        if union is None or tokens[union][0].lower() != 'union':
            raise ValueError('missing_branch_union')
        close = next((j for j in range(union, len(tokens)) if tokens[j][0] == ')' and tokens[j][1] == level - 1), None)
        if close is None:
            raise ValueError('missing_union_end')
        branch = ddl[tokens[start][2]:tokens[union][2]].rstrip()
        names = {name for name in TABLES if '`tb1_' + name + '`' in branch}
        tail = ddl[tokens[union][2]:tokens[close][2]]
        if len(names) != 1 or "'tb3' AS `source_id`" not in tail:
            raise ValueError('unexpected_union_sources')
        name = names.pop()
        if name in found or '`termb4_' + name + '`' in tail:
            raise ValueError('duplicate_union_source')
        found.add(name)
        clone = branch.replace('`tb1_', '`termb4_').replace("'tb1/", "'termb4/")
        clone = clone.replace("'tb1' AS `source_id`", "'termb4' AS `source_id`")
        inserts.append((tokens[close][2], ' union all ' + clone))
    if not inserts:
        raise ValueError('no_matching_live_relations')
    for position, value in reversed(inserts):
        ddl = ddl[:position] + value + ddl[position:]
    return ddl, found


def logical_view(table, columns):
    if table not in TABLES or not columns or any(not c.replace("_", "").isalnum() for c in columns):
        raise ValueError("invalid_logical_view")
    selects = []
    for source in SOURCES:
        expressions = []
        for column in columns:
            value = "`" + column + "`"
            if column in ID_COLUMNS or (table == "peers" and column == "node") or (table == "sync_state" and column == "publisher"):
                value = "CONCAT('" + source + "/'," + value + ")"
            expressions.append(value + " AS `" + column + "`")
        expressions.append("'" + source + "' AS source_id")
        selects.append("SELECT " + ",".join(expressions) + " FROM `hk`.`" + source + "_" + table + "`")
    return "CREATE OR REPLACE SQL SECURITY DEFINER VIEW `hk`.`" + table + "` AS " + " UNION ALL ".join(selects)


def detail_view(ddl):
    # Carry provenance through the existing display-only window and route join.
    old = "`c`.`connection_id` AS `connection_id`"
    if ddl.count(old) != 1 or "`r`.`node` = `c`.`node`" not in ddl:
        raise ValueError("unexpected_detail_view")
    ddl = ddl.replace(old, "`c`.`source_id` AS `source_id`," + old, 1)
    ddl = ddl.replace("partition by case", "partition by `c`.`source_id`,case", 1)
    return ddl.replace("`r`.`node` = `c`.`node`", "`r`.`source_id` = `c`.`source_id` and `r`.`node` = `c`.`node`", 1)


def inline_relations(sql, relations):
    """Expand fixed HK relation references without creating helper SQL views."""
    if set(relations) != set(TABLES):
        raise ValueError("incomplete_hk_relations")
    names = "|".join(re.escape(name) for name in TABLES)
    reference = re.compile(
        r"\b(from|join)\s+(?:(?:`hk`|hk)\.)?(?:`(" + names + r")`|(" + names + r"))"
        r"(?![A-Za-z0-9_])(?P<alias>\s+(?:AS\s+)?`[^`]+`)?", re.IGNORECASE)
    tokens = re.compile(r"`(?:``|[^`])*`|'(?:''|\\.|[^'\\])*'|\"(?:\"\"|\\.|[^\"\\])*\"|/\*[\s\S]*?\*/|--[^\r\n]*")

    def rewrite(chunk):
        for table in TABLES:
            chunk = chunk.replace("`hk`.`" + table + "`.", "`" + table + "`.")

        def expand(match):
            table = (match.group(2) or match.group(3)).lower()
            alias = match.group("alias") or " `" + table + "`"
            return match.group(1) + " (" + relations[table] + ")" + alias

        return reference.sub(expand, chunk)

    out, chunk, end = [], "", 0
    for token in tokens.finditer(sql):
        chunk += sql[end:token.start()]
        value = token.group()
        if value.startswith("`"):
            chunk += value
        else:
            out.extend((rewrite(chunk), value))
            chunk = ""
        end = token.end()
    out.append(rewrite(chunk + sql[end:]))
    return "".join(out)
