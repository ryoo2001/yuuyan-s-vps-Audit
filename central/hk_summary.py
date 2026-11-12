"""HK monthly display SQL: aggregate narrow physical branches before UNION."""
SOURCES = ("tb1", "tb2", "termc", "tb3")
MONTH_START = ("UNIX_TIMESTAMP(CONCAT(DATE_FORMAT(DATE_ADD(UTC_TIMESTAMP(), "
               "INTERVAL 8 HOUR),'%Y-%m'),'-01 00:00:00')) - 28800")


def summary_select():
    """Keep the accepted month, identity, byte, date and ordering contract."""
    keys = ["COALESCE(NULLIF(`" + key + "`,''),'未识别')"
            for key in ("source_ip", "node", "site")]
    branches = []
    latest_branches = []
    for source in SOURCES:
        for table, stamp in (("samples", "ts"), ("traffic_rollup", "latest_ts")):
            latest_branches.append("SELECT MAX(`" + stamp + "`) AS latest_ts FROM `hk`.`"
                + source + "_" + table + "` WHERE `" + stamp + "` >= " + MONTH_START
                + " AND `" + stamp + "` <= UNIX_TIMESTAMP()")
            branches.append(
                "SELECT SQL_BIG_RESULT " + ",".join(expr + " AS `" + name + "`"
                    for expr, name in zip(keys, ("source_ip", "node", "site")))
                + ",MAX(`" + stamp + "`) AS latest_ts,"
                + "SUM(COALESCE(upload_bytes,0)+COALESCE(download_bytes,0)) AS total_bytes"
                + " FROM `hk`.`" + source + "_" + table + "`"
                + " WHERE `" + stamp + "` >= " + MONTH_START
                + " AND `" + stamp + "` <= UNIX_TIMESTAMP()"
                + " GROUP BY " + ",".join(keys))
    return (
        "SELECT SQL_BIG_RESULT CONCAT(DATE_FORMAT(DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR),'%Y/%m/01'),"
        "'–',DATE_FORMAT(TIMESTAMPADD(SECOND,latest.latest_ts,"
        "'1970-01-01 08:00:00'),'%Y/%m/%d')) AS `时间`,"
        "s.source_ip AS `源 IP`,s.node AS `入口机器`,s.site AS `目标网站`,"
        "CASE WHEN SUM(s.total_bytes)>=1000000000 THEN "
        "CONCAT(CAST(ROUND(SUM(s.total_bytes)/1000000000,2) AS DECIMAL(22,2)),' GB') "
        "ELSE CONCAT(CAST(ROUND(SUM(s.total_bytes)/1000000,2) AS DECIMAL(22,2)),' MB') "
        "END AS `流量统计` FROM (" + " UNION ALL ".join(branches) + ") s "
        "CROSS JOIN (SELECT MAX(latest_ts) AS latest_ts FROM ("
        + " UNION ALL ".join(latest_branches) + ") stamps) latest "
        "GROUP BY latest.latest_ts,s.source_ip,s.node,s.site "
        "ORDER BY SUM(s.total_bytes) DESC,s.source_ip,s.node,s.site")


def summary_ddl():
    return ("CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` "
            "SQL SECURITY DEFINER VIEW `hk`.`流量汇总` AS " + summary_select())
