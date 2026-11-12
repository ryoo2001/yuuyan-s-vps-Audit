"""One reviewed HK consolidation transaction; run only with all HK writers paused."""
import json
from pathlib import Path
import sys

sys.path.insert(0, "/usr/local/libexec/traffic-central-hk-store")
import pymysql
from hk_merge import SOURCES, TABLES, logical_view, detail_view


def main():
    if sys.argv[1:] != ["--apply"]:
        raise SystemExit("requires reviewed --apply transaction and paused publishers/pruners")
    root = Path("/var/tmp/hk-merge")
    meta = json.loads((root / "meta.json").read_text())
    password = Path("/etc/traffic-central/root-password").read_text().strip()
    db = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", password=password,
                         charset="utf8mb4", autocommit=True)
    before, after = {}, {}
    renamed = False
    with db.cursor() as c:
        c.execute("SET SESSION lock_wait_timeout=8")
        for source, database in SOURCES.items():
            for table in TABLES:
                c.execute("SELECT COUNT(*) FROM `" + database + "`.`" + table + "`")
                rows = c.fetchone()[0]
                c.execute("CHECKSUM TABLE `" + database + "`.`" + table + "` EXTENDED")
                checksum = c.fetchone()[1]
                assert checksum is not None, "checksum unavailable"
                before[source + "_" + table] = {"rows": rows, "checksum": checksum}
        (root / "before.json").write_text(json.dumps(before))
        renames = ["`" + database + "`.`" + table + "` TO `hk`.`" + source + "_" + table + "`"
                   for source, database in SOURCES.items() for table in TABLES]
        try:
            c.execute("RENAME TABLE " + ",".join(renames))
            renamed = True
            for table in TABLES:
                c.execute(logical_view(table, meta["columns"][table]))
            for name, ddl in meta["views"].items():
                c.execute((detail_view(ddl) if name == "审计明细" else ddl).replace("CREATE ALGORITHM", "CREATE OR REPLACE ALGORITHM", 1))
            for name, expected in before.items():
                c.execute("SELECT COUNT(*) FROM hk.`" + name + "`")
                rows = c.fetchone()[0]
                c.execute("CHECKSUM TABLE hk.`" + name + "` EXTENDED")
                after[name] = {"rows": rows, "checksum": c.fetchone()[1]}
                assert after[name] == expected, "physical table changed: " + name
            for table in TABLES:
                c.execute("SELECT COUNT(*) FROM hk.`" + table + "`")
                assert c.fetchone()[0] == sum(before[source + "_" + table]["rows"] for source in SOURCES)
        except Exception:
            if renamed:
                for table in TABLES:
                    c.execute("DROP VIEW IF EXISTS hk.`" + table + "`")
                reverse = ["`hk`.`" + source + "_" + table + "` TO `" + database + "`.`" + table + "`"
                           for source, database in SOURCES.items() for table in TABLES]
                c.execute("RENAME TABLE " + ",".join(reverse))
                for ddl in meta["views"].values():
                    c.execute(ddl.replace("CREATE ALGORITHM", "CREATE OR REPLACE ALGORITHM", 1))
            raise
    result = {"physical_tables": 27, "logical_views": 9, "friendly_views": 5,
              "before": before, "after": after, "all_rows_and_checksums_equal": True}
    (root / "result.json").write_text(json.dumps(result))
    print(json.dumps({k: v for k, v in result.items() if k not in ("before", "after")}))
    db.close()


if __name__ == "__main__":
    main()
