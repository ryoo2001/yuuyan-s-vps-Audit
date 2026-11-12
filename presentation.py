"""Human-readable SQLite view. No raw identity fallback or cumulative-byte rates."""
import ipaddress

COLUMNS = ("时间", "源 IP", "隧道内网 IP（入口机器）", "目标网站", "最近上传速率", "最近下载速率")
DETAIL_DEDUP_WINDOW_SECONDS = 5
DETAIL_DEDUP_BASIS = "source_ip_site_entry_fixed_window"
SUMMARY_VIEW_COLUMNS = ("时间", "源 IP", "入口机器", "目标网站", "流量统计")
SUMMARY_VIEW_SCOPE = "current_beijing_calendar_month_to_latest"
SUMMARY_VIEW_GROUPING = "source_ip_node_site"
SUMMARY_VIEW_TIME_BASIS = "beijing_month_start_to_latest_sample_date"


def install(db, config):
    # A single row per connection; historical rates are anchored to last_seen.
    db.execute("""CREATE TABLE IF NOT EXISTS connection_rates(
        connection_id TEXT PRIMARY KEY, observed_at REAL, interval_seconds REAL,
        upload_bps REAL, download_bps REAL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS entry_routes(
        node TEXT, inbound_port INTEGER, tunnel_ip TEXT,
        PRIMARY KEY(node,inbound_port))""")
    routes = []
    for route in config.get("entry_routes", []):
        node, port, address = route["node"], route["inbound_port"], route["tunnel_ip"]
        if node not in config.get("peers", {}) or type(port) is not int or port not in config["inbound_ports"]:
            raise ValueError("unverified entry route")
        if address is not None:
            address = str(ipaddress.ip_address(address))
        routes.append((node, port, address))
    db.execute("DELETE FROM entry_routes")
    db.executemany("INSERT INTO entry_routes VALUES(?,?,?)", routes)
    db.execute("CREATE INDEX IF NOT EXISTS connection_seen ON connection_state(last_seen DESC)")

    def rate(column):
        # Decimal units: 1000 B/s = 1 KB/s; 1000 KB/s = 1 MB/s.
        return f"""CASE WHEN c.source_ip IS NULL OR c.source_ip='' OR r.interval_seconds IS NULL OR r.interval_seconds<>5 OR r.observed_at != c.last_seen OR r.{column} IS NULL THEN '未采样'
          WHEN r.{column} >= 1000000 THEN printf('%.2f MB/s', r.{column}/1000000.0)
          ELSE printf('%.2f KB/s', r.{column}/1000.0) END"""

    db.execute('DROP VIEW IF EXISTS "审计明细"')
    db.execute(f"""CREATE VIEW "审计明细" AS SELECT
        strftime('%Y/%m/%d %H:%M:%S',c.last_seen,'unixepoch','+8 hours') AS "时间",
        COALESCE(NULLIF(c.source_ip,''),'未识别') AS "源 IP",
        CASE WHEN c.node IS NULL OR c.node='' THEN
            CASE WHEN e.node IS NULL THEN '未识别'
                 WHEN e.tunnel_ip IS NULL THEN '直连（' || e.node || '；未经过隧道）'
                 ELSE e.tunnel_ip || '（' || e.node || '）' END
          WHEN e.node IS NULL AND (c.source_ip IS NULL OR c.source_ip='') THEN '未识别'
          WHEN e.node IS NULL THEN '未核验（' || c.node || '）'
          WHEN e.tunnel_ip IS NULL THEN '直连（' || c.node || '；未经过隧道）'
          ELSE e.tunnel_ip || '（' || c.node || '）' END AS "隧道内网 IP（入口机器）",
        c.site AS "目标网站",
        {rate('upload_bps')} AS "最近上传速率",
        {rate('download_bps')} AS "最近下载速率"
      FROM (
        SELECT c.*,
          ROW_NUMBER() OVER (
            PARTITION BY
              CASE WHEN c.connection_id IS NULL OR c.source_ip IS NULL OR c.source_ip=''
                          OR c.site IS NULL OR c.site='' OR lower(c.site)='unknown'
                          OR c.node IS NULL OR c.node='' OR c.inbound_port IS NULL
                          OR c.last_seen IS NULL
                     THEN c.connection_id ELSE c.source_ip END,
              c.site,
              CASE WHEN c.node IS NULL OR c.node='' THEN c.connection_id ELSE c.node END,
              c.inbound_port,
              CASE WHEN c.last_seen IS NULL THEN c.connection_id
                   ELSE CAST((c.last_seen + 2.5) / 5 AS INTEGER) END
            ORDER BY c.last_seen DESC, c.connection_id
          ) AS _session_rank
        FROM connection_state c
      ) c
      LEFT JOIN entry_routes e ON (e.node=c.node AND e.inbound_port=c.inbound_port) OR (COALESCE(c.node,'')='' AND e.tunnel_ip=c.source_peer)
      LEFT JOIN connection_rates r ON r.connection_id=c.connection_id
      WHERE c._session_rank=1
      ORDER BY c.last_seen DESC, c.connection_id""")

    # Month-to-date view: one aggregate per source IP, ingress node and site.
    # The first column is an explicit Beijing date range, not a timestamp.
    # Old raw samples are folded into traffic_rollup before retention pruning;
    # keep the view as one snapshot over both durable totals and live rows.
    db.execute('DROP VIEW IF EXISTS "流量汇总"')
    db.execute("""CREATE VIEW "流量汇总" AS
      WITH summary_rows AS (
        SELECT ts,source_ip,node,site,upload_bytes,download_bytes FROM samples
        UNION ALL
        SELECT latest_ts,source_ip,node,site,upload_bytes,download_bytes FROM traffic_rollup
      ), month_window AS (
        SELECT CAST(strftime('%s',strftime('%Y-%m-01 00:00:00','now','+8 hours')) AS INTEGER)-28800 AS month_start,
          CAST(strftime('%s','now') AS INTEGER) AS now_ts
      ), filtered AS (
        SELECT s.* FROM summary_rows s CROSS JOIN month_window w
        WHERE s.ts >= w.month_start AND s.ts <= w.now_ts
      ), latest AS (
        SELECT COALESCE(MAX(ts),CAST(strftime('%s','now') AS INTEGER)) AS latest_ts FROM filtered
      )
      SELECT strftime('%Y/%m/01','now','+8 hours') || '–' ||
          strftime('%Y/%m/%d',latest.latest_ts,'unixepoch','+8 hours') AS "时间",
        COALESCE(NULLIF(s.source_ip,''),'未识别') AS "源 IP",
        COALESCE(NULLIF(s.node,''),'未识别') AS "入口机器",
        COALESCE(NULLIF(s.site,''),'未识别') AS "目标网站",
        CASE WHEN SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0)) >= 1000000000
          THEN printf('%.2f GB', SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0))/1000000000.0)
          ELSE printf('%.2f MB', SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0))/1000000.0) END AS "流量统计"
      FROM filtered s CROSS JOIN latest
      GROUP BY latest.latest_ts, COALESCE(NULLIF(s.source_ip,''),'未识别'),
        COALESCE(NULLIF(s.node,''),'未识别'), COALESCE(NULLIF(s.site,''),'未识别')
      ORDER BY SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0)) DESC, 2, 3, 4""" )
