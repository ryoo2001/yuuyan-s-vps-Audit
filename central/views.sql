CREATE TABLE IF NOT EXISTS sync_state (
  publisher VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
  epoch CHAR(32) NOT NULL,
  last_seq BIGINT UNSIGNED NOT NULL,
  last_received DOUBLE NOT NULL,
  sent_at DOUBLE NOT NULL,
  missing_rows BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Daily totals survive pruning of the short raw-sample window. Unknown values
-- are stored as empty strings so the composite key remains unique in MySQL.
CREATE TABLE IF NOT EXISTS traffic_rollup (
  day_start BIGINT UNSIGNED NOT NULL,
  source_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  node VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  site VARCHAR(253) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  upload_bytes BIGINT UNSIGNED NOT NULL,
  download_bytes BIGINT UNSIGNED NOT NULL,
  latest_ts DOUBLE NOT NULL,
  PRIMARY KEY (day_start,source_ip,node,site),
  KEY by_day (day_start),
  KEY by_latest (latest_ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW `审计明细` AS
SELECT
 DATE_FORMAT(TIMESTAMPADD(SECOND,FLOOR(c.last_seen),'1970-01-01 08:00:00'),'%Y/%m/%d %H:%i:%s') AS `时间`,
 COALESCE(NULLIF(c.source_ip,''),'未识别') AS `源 IP`,
 CASE WHEN c.source_peer='172.30.3.3' AND (c.node IS NULL OR c.node='')
           THEN '172.30.3.3（云厂入口：203.0.113.103）'
      WHEN c.node IS NULL OR c.node='' THEN
           CASE WHEN r.node IS NULL THEN '未识别'
                WHEN r.tunnel_ip IS NULL THEN CONCAT('直连（',r.node,'；未经过隧道）')
                ELSE CONCAT(r.tunnel_ip,'（',r.node,'）') END
      WHEN r.node IS NULL AND (c.source_ip IS NULL OR c.source_ip='') THEN '未识别'
      WHEN r.node IS NULL THEN CONCAT('未核验（',c.node,'）')
      WHEN r.tunnel_ip IS NULL THEN CONCAT('直连（',c.node,'；未经过隧道）')
      ELSE CONCAT(r.tunnel_ip,'（',c.node,'）') END AS `隧道内网 IP（入口机器）`,
 c.site AS `目标网站`,
 CASE WHEN c.source_ip IS NULL OR c.source_ip='' OR v.interval_seconds IS NULL OR v.interval_seconds<>5 OR v.observed_at<>c.last_seen OR v.upload_bps IS NULL THEN '未采样'
      WHEN v.upload_bps<1000000 THEN CONCAT(CAST(ROUND(v.upload_bps/1000,2) AS DECIMAL(22,2)),' KB/s')
      ELSE CONCAT(CAST(ROUND(v.upload_bps/1000000,2) AS DECIMAL(22,2)),' MB/s') END AS `最近上传速率`,
 CASE WHEN c.source_ip IS NULL OR c.source_ip='' OR v.interval_seconds IS NULL OR v.interval_seconds<>5 OR v.observed_at<>c.last_seen OR v.download_bps IS NULL THEN '未采样'
      WHEN v.download_bps<1000000 THEN CONCAT(CAST(ROUND(v.download_bps/1000,2) AS DECIMAL(22,2)),' KB/s')
      ELSE CONCAT(CAST(ROUND(v.download_bps/1000000,2) AS DECIMAL(22,2)),' MB/s') END AS `最近下载速率`
FROM (
 SELECT c.connection_id,c.last_seen,c.source_peer,c.inbound_port,c.site,c.source_ip,c.node,
   ROW_NUMBER() OVER (
     PARTITION BY
       CASE WHEN c.connection_id IS NULL OR c.source_ip IS NULL OR c.source_ip=''
                    OR c.site IS NULL OR c.site='' OR LOWER(c.site)='unknown'
                    OR c.node IS NULL OR c.node='' OR c.inbound_port IS NULL
                    OR c.last_seen IS NULL
              THEN c.connection_id ELSE c.source_ip END,
       c.site,
       CASE WHEN c.node IS NULL OR c.node='' THEN c.connection_id ELSE c.node END,
       c.inbound_port,
       CASE WHEN c.last_seen IS NULL THEN c.connection_id
            ELSE FLOOR((c.last_seen + 2.5) / 5) END
     ORDER BY c.last_seen DESC, c.connection_id
   ) AS _session_rank
 FROM connection_state c
) c
LEFT JOIN connection_rates v ON v.connection_id=c.connection_id
LEFT JOIN entry_routes r ON (r.node=c.node AND r.inbound_port=c.inbound_port) OR (COALESCE(c.node,'')='' AND r.tunnel_ip=c.source_peer)
WHERE c._session_rank=1
ORDER BY c.last_seen DESC, c.connection_id;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW `流量汇总` AS
WITH summary_rows AS (
  SELECT ts,source_ip,node,site,upload_bytes,download_bytes FROM samples
  UNION ALL
  SELECT latest_ts,source_ip,node,site,upload_bytes,download_bytes FROM traffic_rollup
), month_window AS (
  SELECT UNIX_TIMESTAMP(CONCAT(DATE_FORMAT(DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR),'%Y-%m'),'-01 00:00:00')) - 28800 AS month_start,
         UNIX_TIMESTAMP() AS now_ts
), filtered AS (
  SELECT s.* FROM summary_rows s CROSS JOIN month_window w
  WHERE s.ts >= w.month_start AND s.ts <= w.now_ts
), latest AS (
  SELECT COALESCE(MAX(ts),UNIX_TIMESTAMP()) AS latest_ts FROM filtered
)
SELECT CONCAT(
         DATE_FORMAT(DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR),'%Y/%m/01'),
         '–',
         DATE_FORMAT(TIMESTAMPADD(SECOND,latest.latest_ts,'1970-01-01 08:00:00'),'%Y/%m/%d')
       ) AS `时间`,
 COALESCE(NULLIF(s.source_ip,''),'未识别') AS `源 IP`,
 COALESCE(NULLIF(s.node,''),'未识别') AS `入口机器`,
 COALESCE(NULLIF(s.site,''),'未识别') AS `目标网站`,
 CASE WHEN SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0)) >= 1000000000
      THEN CONCAT(CAST(ROUND(SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0))/1000000000,2) AS DECIMAL(22,2)),' GB')
      ELSE CONCAT(CAST(ROUND(SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0))/1000000,2) AS DECIMAL(22,2)),' MB') END AS `流量统计`
FROM filtered s CROSS JOIN latest
GROUP BY latest.latest_ts, COALESCE(NULLIF(s.source_ip,''),'未识别'), COALESCE(NULLIF(s.node,''),'未识别'), COALESCE(NULLIF(s.site,''),'未识别')
ORDER BY SUM(COALESCE(s.upload_bytes,0)+COALESCE(s.download_bytes,0)) DESC, `源 IP`, `入口机器`, `目标网站`;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW `入口流量汇总` AS
SELECT DATE_FORMAT(TIMESTAMPADD(SECOND,bucket,'1970-01-01 08:00:00'),'%Y/%m/%d %H:%i:%s') AS `时间`,
 source_ip AS `源 IP`,node AS `入口机器`,transport AS `传输协议`,
 CASE WHEN SUM(up_bytes)<1000000 THEN CONCAT(CAST(ROUND((SUM(up_bytes))/1000,2) AS DECIMAL(22,2)),' KB') ELSE CONCAT(CAST(ROUND((SUM(up_bytes))/1000000,2) AS DECIMAL(22,2)),' MB') END AS `上行线路流量`,
 CASE WHEN SUM(down_bytes)<1000000 THEN CONCAT(CAST(ROUND((SUM(down_bytes))/1000,2) AS DECIMAL(22,2)),' KB') ELSE CONCAT(CAST(ROUND((SUM(down_bytes))/1000000,2) AS DECIMAL(22,2)),' MB') END AS `下行线路流量`,
 CASE WHEN SUM(up_bytes)/60<1000000 THEN CONCAT(CAST(ROUND((SUM(up_bytes)/60)/1000,2) AS DECIMAL(22,2)),' KB/s') ELSE CONCAT(CAST(ROUND((SUM(up_bytes)/60)/1000000,2) AS DECIMAL(22,2)),' MB/s') END AS `分钟平均上传速率`,
 CASE WHEN SUM(down_bytes)/60<1000000 THEN CONCAT(CAST(ROUND((SUM(down_bytes)/60)/1000,2) AS DECIMAL(22,2)),' KB/s') ELSE CONCAT(CAST(ROUND((SUM(down_bytes)/60)/1000000,2) AS DECIMAL(22,2)),' MB/s') END AS `分钟平均下载速率`
FROM wire_samples WHERE bucket < FLOOR(UNIX_TIMESTAMP()/60)*60 GROUP BY bucket,source_ip,node,transport;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW `访问记录` AS
SELECT DATE_FORMAT(TIMESTAMPADD(SECOND,FLOOR(ts),'1970-01-01 08:00:00'),'%Y/%m/%d %H:%i:%s') AS `时间`,
 COALESCE(source_ip,'未识别') AS `源 IP`,COALESCE(node,'未识别') AS `入口机器`,site AS `目标网站`,quality AS `归属依据`
FROM visits ORDER BY ts DESC;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW `同步状态` AS
SELECT publisher AS `采集节点`,
 DATE_FORMAT(TIMESTAMPADD(SECOND,FLOOR(last_received),'1970-01-01 08:00:00'),'%Y/%m/%d %H:%i:%s') AS `最后入库时间`,
 ROUND(GREATEST(0,UNIX_TIMESTAMP(CURRENT_TIMESTAMP(6))-last_received),1) AS `距上次同步秒`,last_seq AS `确认位置`,missing_rows AS `单批最大缺失数`,
 '流量为采样下界；明细为同源 IP 近5秒均速；流量汇总为北京时间当月1日至最新样本' AS `统计说明`
FROM sync_state;
