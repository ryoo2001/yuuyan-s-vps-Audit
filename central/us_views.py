"""US-specific egress projections built on the shared regional views."""
from pathlib import Path
import re

try:
    import region
except ImportError:  # pragma: no cover - deployment runs modules from this directory
    from . import region


MAPPING_TABLE = "us_egress_nodes"
DEFAULT_MAPPINGS = (
    ("term-d-direct", "term-d", "direct", None),
    ("term-d", "term-d", "direct", None),
    ("egress-d-direct", "egress-d", "socks5", "term-d"),
    ("egress-d", "egress-d", "socks5", "term-d"),
)


def install_mapping(db, database="us", mappings=DEFAULT_MAPPINGS):
    table = "`" + database + "`.`" + MAPPING_TABLE + "`"
    with db.cursor() as cursor:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS " + table + " ("
            "audit_node VARCHAR(64) NOT NULL PRIMARY KEY,"
            "egress_node VARCHAR(64) NOT NULL,"
            "route_type VARCHAR(32) NOT NULL,"
            "upstream_node VARCHAR(64) NULL,"
            "updated_at DOUBLE NOT NULL)"
        )
        cursor.executemany(
            "INSERT INTO " + table + " (audit_node,egress_node,route_type,upstream_node,updated_at) "
            "VALUES(%s,%s,%s,%s,UNIX_TIMESTAMP()) "
            "ON DUPLICATE KEY UPDATE egress_node=VALUES(egress_node),"
            "route_type=VALUES(route_type),upstream_node=VALUES(upstream_node),"
            "updated_at=VALUES(updated_at)", mappings
        )


def view_ddls(database="us", views_path=None):
    root = Path(views_path or Path(__file__).with_name("views.sql"))
    ddls = region.base_view_ddls(database, ("",), root.read_text(encoding="utf-8"))
    table = "`" + database + "`.`" + MAPPING_TABLE + "`"
    detail = ("COALESCE((SELECT e.egress_node FROM " + table +
              " e WHERE e.audit_node=c.node LIMIT 1),NULLIF(c.node,''),'未识别') AS `出口机器`")
    ddls["审计明细"] = re.sub(
        r"CASE WHEN c[.]source_peer=.*?END AS `隧道内网 IP（入口机器）`",
        detail, ddls["审计明细"], count=1, flags=re.S
    )
    if "隧道内网 IP（入口机器）" in ddls["审计明细"]:
        raise ValueError("us_detail_projection_not_rewritten")
    ddls["流量汇总"] = ddls["流量汇总"].replace(
        "s.node AS `入口机器`",
        "COALESCE((SELECT e.egress_node FROM " + table +
        " e WHERE e.audit_node=s.node LIMIT 1),NULLIF(s.node,''),'未识别') AS `出口机器`", 1)
    ddls["入口流量汇总"] = ddls["入口流量汇总"].replace(
        "node AS `入口机器`",
        "COALESCE((SELECT e.egress_node FROM " + table +
        " e WHERE e.audit_node=node LIMIT 1),NULLIF(node,''),'未识别') AS `出口机器`", 1)
    ddls["访问记录"] = ddls["访问记录"].replace(
        "COALESCE(node,'未识别') AS `入口机器`",
        "COALESCE((SELECT e.egress_node FROM " + table +
        " e WHERE e.audit_node=node LIMIT 1),NULLIF(node,''),'未识别') AS `出口机器`", 1)
    return ddls


def install_views(db, database="us", views_path=None):
    with db.cursor() as cursor:
        for name, ddl in view_ddls(database, views_path).items():
            if name != "同步状态":
                cursor.execute(ddl)
