#!/usr/bin/env python3
"""Add term-b4 to the existing HK query contract without rebuilding other sources."""
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, '/tmp/termb4-audit-task')
sys.path.insert(0, '/usr/local/libexec/traffic-central-storage')
import pymysql
import hk_merge
import storage

RELATIONS = Path('/usr/local/libexec/traffic-central-hk-store/relations.json')
BACKUP = Path('/tmp/termb4-audit-task/views-backup.json')
VIEWS = {
    '审计明细': {'connection_rates', 'connection_state', 'entry_routes'},
    '入口流量汇总': {'wire_samples'},
    '访问记录': {'visits'},
    '同步状态': {'sync_state'},
}
PREFIXES = ('tb1_', 'tb2_', 'termc_', 'tb3_', 'termb4_')


def select_body(ddl):
    match = re.search(r'\bVIEW\s+(?:`[^\x60]+`\.)?`[^\x60]+`\s+AS\s+', ddl, re.I)
    if not match:
        raise ValueError('unexpected_view_ddl')
    return ddl[match.end():]


def replace_ddl(ddl):
    result, count = re.subn(r'^CREATE\s+', 'CREATE OR REPLACE ', ddl, count=1, flags=re.I)
    if count != 1:
        raise ValueError('unexpected_create')
    return result


def main():
    if BACKUP.exists():
        raise ValueError('task_backup_already_exists')
    old_relations = RELATIONS.read_text()
    extended = hk_merge.append_namespace(json.loads(old_relations), 'termb4')
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                         database='hk', charset='utf8mb4', autocommit=True)
    applied = []
    try:
        with db.cursor() as cursor:
            cursor.execute('SET SESSION lock_wait_timeout=4')
            originals, candidates = {}, {}
            for name, expected in VIEWS.items():
                cursor.execute('SHOW CREATE VIEW `' + name + '`')
                originals[name] = cursor.fetchone()[1]
                candidate, found = hk_merge.extend_normalized_view(originals[name], 'termb4')
                if found != expected:
                    raise ValueError('unexpected_view_sources:' + name)
                candidates[name] = replace_ddl(candidate)
            cursor.execute('SHOW CREATE VIEW `流量汇总`')
            originals['流量汇总'] = cursor.fetchone()[1]
            candidates['流量汇总'] = storage.summary_ddl('hk', PREFIXES)
            for name, ddl in candidates.items():
                cursor.execute('EXPLAIN SELECT * FROM (' + select_body(ddl) + ') AS candidate LIMIT 1')
                cursor.fetchall()
            BACKUP.write_text(json.dumps({'views': originals, 'relations': old_relations}, ensure_ascii=False))
            os.chmod(BACKUP, 0o600)
            try:
                for name, ddl in candidates.items():
                    cursor.execute('SHOW CREATE VIEW `' + name + '`')
                    if cursor.fetchone()[1] != originals[name]:
                        raise ValueError('view_changed_during_preparation:' + name)
                    cursor.execute(ddl)
                    applied.append(name)
                tmp = RELATIONS.with_name('relations.json.termb4-task')
                tmp.write_text(json.dumps(extended, ensure_ascii=False, indent=2) + '\n')
                os.chmod(tmp, RELATIONS.stat().st_mode & 0o777)
                os.replace(tmp, RELATIONS)
            except Exception:
                for name in reversed(applied):
                    cursor.execute(replace_ddl(originals[name]))
                raise
            print(json.dumps({'views': list(candidates), 'relations': len(extended)}, ensure_ascii=False))
    finally:
        db.close()


if __name__ == '__main__':
    main()
