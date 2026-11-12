#!/usr/bin/env python3
"""Provision the empty HK term-b4 namespace; never touch existing sources."""
import json
import sys

sys.path.insert(0, '/usr/local/libexec/traffic-central-storage')
import pymysql
import region
import tiering
import monthbook

TABLES = ('samples', 'visits', 'wire_samples', 'connection_state', 'connection_rates',
          'entry_routes', 'peers', 'sync_state', 'traffic_rollup')


def main():
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root',
                         database='hk', charset='utf8mb4', autocommit=True)
    try:
        with db.cursor() as cursor:
            cursor.execute('SET SESSION lock_wait_timeout=4')
            cursor.execute('SET SESSION innodb_lock_wait_timeout=4')
            cursor.execute("SELECT table_name FROM information_schema.tables "
                           "WHERE table_schema='hk' AND table_name LIKE 'termb4\\_%'")
            existing = {row[0] for row in cursor.fetchall()}
            unexpected = existing - {'termb4_' + table for table in TABLES} - {'termb4_traffic_monthly', 'termb4_edge_queue'}
            if unexpected:
                raise ValueError('unexpected_namespace_tables')
            for name in TABLES:
                cursor.execute('CREATE TABLE IF NOT EXISTS `hk`.`termb4_' + name + '` LIKE `hk`.`tb1_' + name + '`')
            cursor.execute('CREATE TABLE IF NOT EXISTS `hk`.`termb4_edge_queue` ('
                           'batch_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,'
                           'created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),'
                           'body MEDIUMBLOB NOT NULL,KEY by_created(created_at,batch_id)) '
                           'ENGINE=InnoDB')
        result = region.install_namespace(db, 'hk', 'termb4_')
        tiers = tiering.install_namespace(db, 'hk', 'termb4_')
        monthbook.install(db, 'hk', 'termb4_')
        print(json.dumps({'storage': result, 'retention': tiers, 'calendar': 'ready'}))
    finally:
        db.close()


if __name__ == '__main__':
    main()
