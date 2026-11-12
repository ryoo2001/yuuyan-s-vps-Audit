"""Fixed, versioned row contract for the single LINKA publisher."""
import math

TABLES = {
    'samples': ('event_id ts connection_id node source_ip site upload_bytes download_bytes quality'.split(), ['event_id'], 'ts'),
    'visits': ('event_id ts node source_ip site destination_port network flow_id quality'.split(), ['event_id'], 'ts'),
    'wire_samples': ('bucket node source_ip entry_port transport up_bytes down_bytes up_packets down_packets'.split(), 'bucket node source_ip entry_port transport'.split(), 'bucket'),
    'connection_state': ('connection_id start_ts last_seen source_peer source_port inbound_port site prev_up prev_down flow_id source_ip node quality'.split(), ['connection_id'], 'last_seen'),
    'connection_rates': ('connection_id observed_at interval_seconds upload_bps download_bps'.split(), ['connection_id'], 'observed_at'),
    'entry_routes': ('node inbound_port tunnel_ip'.split(), ['node', 'inbound_port'], None),
    'peers': ('node last_received sender_ts metrics'.split(), ['node'], None),
}
FLOATS = set('ts start_ts last_seen observed_at interval_seconds upload_bps download_bps last_received sender_ts'.split())
INTS = set('bucket source_port inbound_port destination_port entry_port upload_bytes download_bytes prev_up prev_down up_bytes down_bytes up_packets down_packets'.split())
LENGTHS = {'event_id': 160, 'connection_id': 80, 'flow_id': 160, 'node': 64, 'source_ip': 45, 'source_peer': 45, 'tunnel_ip': 45, 'site': 253, 'quality': 64, 'network': 16, 'transport': 16, 'metrics': 32768}


def validate_row(table, values):
    if not isinstance(table, str) or table not in TABLES or not isinstance(values, list) or len(values) != len(TABLES[table][0]):
        raise ValueError('invalid_row_shape')
    for name, value in zip(TABLES[table][0], values):
        if value is None:
            if name in TABLES[table][1]:
                raise ValueError('null_primary_key')
            continue
        if name in INTS:
            if type(value) is not int or not 0 <= value <= 9223372036854775807:
                raise ValueError('invalid_integer')
            if 'port' in name and value > 65535:
                raise ValueError('invalid_port')
        elif name in FLOATS:
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('invalid_number')
        elif not isinstance(value, str) or len(value) > LENGTHS[name] or '\x00' in value:
            raise ValueError('invalid_string')
    return values


def create_table_sql(table):
    columns, keys, stamp = TABLES[table]
    defs = []
    for name in columns:
        kind = 'DOUBLE' if name in FLOATS else 'BIGINT UNSIGNED' if name in INTS else (
            'MEDIUMTEXT' if name == 'metrics' else f'VARCHAR({LENGTHS[name]})')
        # Index identity is byte-sensitive; do not merge case-distinct IDs or nodes.
        if name not in FLOATS | INTS and name != 'metrics':
            kind += ' COLLATE utf8mb4_bin'
        defs.append(f'`{name}` {kind}' + (' NOT NULL' if name in keys else ' NULL'))
    defs += ['`_seq` BIGINT UNSIGNED NOT NULL', 'PRIMARY KEY (' + ','.join(f'`{k}`' for k in keys) + ')']
    if stamp and stamp not in keys:
        defs.append(f'KEY `by_time` (`{stamp}`)')
    # samples has no connection_id index: central readers and upserts never filter on it.
    # New regions receive selective reader indexes from the shared storage contract.
    if table in ('samples', 'visits', 'connection_state'):
        defs.append(f'KEY by_source_time (`source_ip`,`{stamp}`)')
        defs.append(f'KEY by_site_time (`site`,`{stamp}`)')
    return f'CREATE TABLE IF NOT EXISTS `{table}` (' + ','.join(defs) + ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin'


def upsert_sql(table):
    columns, keys, _ = TABLES[table]
    names = columns + ['_seq']
    updates = [f'`{c}`=IF(VALUES(`_seq`)>`_seq`,VALUES(`{c}`),`{c}`)' for c in columns if c not in keys]
    updates.append('`_seq`=GREATEST(`_seq`,VALUES(`_seq`))')
    return (f'INSERT INTO `{table}` (' + ','.join(f'`{c}`' for c in names) + ') VALUES (' +
            ','.join(['%s'] * len(names)) + ') ON DUPLICATE KEY UPDATE ' + ','.join(updates))
