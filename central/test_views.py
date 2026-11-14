"""Real-MySQL SELECT tests over session-only temporary fixtures, never real rows."""
import re
import time


def check_views(db, text, summary_sql=None):
    statements = {re.search(r"VIEW `([^`]+)` AS", s).group(1): re.split(r"\bAS\s+(?=(?:SELECT|WITH)\b)", s, 1)[1]
                   for s in text.split(";") if " VIEW `" in s}
    if summary_sql is not None:
        statements['流量汇总'] = summary_sql
    with db.cursor() as c:
        for table in ["samples", "traffic_rollup", "wire_samples", "connection_state", "connection_rates", "entry_routes"]:
            c.execute("SHOW CREATE TABLE `"+table+"`")
            ddl=c.fetchone()[1].replace("CREATE TABLE ", "CREATE TEMPORARY TABLE ", 1)
            c.execute(ddl)
        c.execute("CREATE TEMPORARY TABLE ip_geo (source_ip VARCHAR(45) PRIMARY KEY,location VARCHAR(255) NOT NULL,"
                  "country VARCHAR(128) NOT NULL,province VARCHAR(128) NOT NULL,city VARCHAR(128) NOT NULL,"
                  "isp VARCHAR(128) NOT NULL,lookup_status VARCHAR(32) NOT NULL,db_version VARCHAR(96) NOT NULL,"
                  "updated_at DOUBLE NOT NULL)")
        c.execute("INSERT INTO ip_geo VALUES(%s,%s,'','','','','matched','fixture',%s)",
                  ('198.51.100.1', '江苏省-南京市 电信', time.time()))
        minute = int(time.time()//60)*60
        for eid, stamp, source, site, up, down in [
            ("old1", minute-60, "198.51.100.1", "example.test", 30000, 30000000),
            ("old2", minute-60, "198.51.100.1", "example.test", 30000, 30000000),
            ("partial", minute, "198.51.100.2", "latest.test", 1500000000, 0),
        ]:
            c.execute("INSERT INTO samples(event_id,ts,connection_id,node,source_ip,site,upload_bytes,download_bytes,_seq) VALUES(%s,%s,%s,'edge',%s,%s,%s,%s,1)",
                      (eid, stamp, eid, source, site, up, down))
        c.execute(statements['流量汇总']); rows=c.fetchall(); cols=[r[0] for r in c.description]
        assert cols == ['时间','源 IP','IP归属地','入口机器','目标网站','流量统计'], cols
        assert len(rows)==2 and not any('字节' in col for col in cols)
        summary_rows={r[4]:dict(zip(cols,r)) for r in rows}
        assert summary_rows['example.test']['流量统计']=='60.06 MB', summary_rows
        assert summary_rows['example.test']['IP归属地']=='江苏省-南京市 电信'
        assert summary_rows['latest.test']['IP归属地']=='未查询'
        assert summary_rows['latest.test']['流量统计']=='1.50 GB', summary_rows
        beijing_day=time.strftime('%Y/%m/%d', time.gmtime(minute+8*3600))
        assert summary_rows['example.test']['时间']==beijing_day[:7]+'/01–'+beijing_day, summary_rows
        for stamp, up, down in [(minute-60, 120000, 120000000), (minute, 999999999, 999999999)]:
            c.execute("INSERT INTO wire_samples(bucket,node,source_ip,entry_port,transport,up_bytes,down_bytes,_seq) VALUES(%s,'edge','198.51.100.1',1234,'tcp',%s,%s,1)", (stamp,up,down))
        c.execute(statements['入口流量汇总']); rows=c.fetchall(); cols=[r[0] for r in c.description]
        assert len(rows)==1 and not any('字节' in col for col in cols)
        row=dict(zip(cols,rows[0]))
        assert row['上行线路流量']=='120.00 KB' and row['下行线路流量']=='120.00 MB', row
        assert row['分钟平均上传速率']=='2.00 KB/s' and row['分钟平均下载速率']=='2.00 MB/s', row
        for cid, ip, peer, interval in [('valid','198.51.100.1','10.77.250.1',5),
                                      ('legacy','198.51.100.2','10.77.250.1',0.5),
                                      ('unknown',None,'172.30.3.3',5),
                                      ('warmup','198.51.100.3','10.77.250.1',None)]:
            c.execute("INSERT INTO connection_state(connection_id,last_seen,source_ip,source_peer,site,_seq) VALUES(%s,%s,%s,%s,%s,1)", (cid, minute-1,ip,peer,cid))
            c.execute("INSERT INTO connection_rates(connection_id,observed_at,interval_seconds,upload_bps,download_bps,_seq) VALUES(%s,%s,%s,2000,2000000,1)", (cid,minute-1,interval))
        c.executemany(
            "INSERT INTO connection_state(connection_id,last_seen,source_ip,source_peer,inbound_port,site,node,_seq) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,1)",
            [
                ("dedup-a", minute-1, "198.51.100.9", "10.77.250.1", 31100, "same.example", "edge"),
                ("dedup-b", minute-1, "198.51.100.9", "10.77.250.1", 31100, "same.example", "edge"),
            ],
        )
        c.execute(statements['审计明细']); cols=[r[0] for r in c.description]
        detail_rows=c.fetchall()
        details={r[4]:dict(zip(cols,r)) for r in detail_rows}
        assert len([r for r in detail_rows if r[4]=='same.example']) == 1
        assert all(len(row['时间']) == 16 for row in details.values())
        assert all('最近上传速率' not in row and '最近下载速率' not in row for row in details.values())
        assert details['unknown']['源 IP']=='未识别'
        assert details['valid']['IP归属地']=='江苏省-南京市 电信'
        assert details['unknown']['IP归属地']=='未识别'
        assert details['unknown']['隧道内网 IP（入口机器）']=='172.30.3.3（云厂入口：203.0.113.103）'
    return {'mysql_select_fixtures_passed': True, 'production_rows_untouched': True,
            'checks': ['monthly_source_ip_site_grouping','adaptive_mb_gb','latest_sample_included',
                       'minute_details','rate_reads_removed','summary_geolocation','unknown_source_not_aggregated','provider_mapping_kept']}
