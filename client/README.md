# 连接审计数据库

可使用任意支持 MySQL 的客户端（如 Navicat、DBeaver 或 `mysql` 命令行）直接连接中心地址的 TCP 3306 端口，无需 SSH 转发。账号为只读账号 `audit_ro`，可访问全部地区数据库，连接后执行 `SHOW DATABASES;` 即可列出。地址和密码由部署方通过私密渠道提供，不写入仓库。

命令行连接示例：

```bash
mysql -h <中心地址> -P 3306 -u audit_ro -p
```

## 查询示例

选择数据库后执行：

```sql
SELECT * FROM `审计明细` LIMIT 50;
SELECT * FROM `流量汇总` LIMIT 50;
SELECT * FROM `入口流量汇总` LIMIT 50;
SELECT * FROM `访问记录` LIMIT 50;
SELECT * FROM `同步状态`;
```

`审计明细` 与 `流量汇总` 提供 `IP归属地` 列，格式为 `省/直辖市-城市 运营商`。归属地由中心定时缓存公开 ip2region 数据，尚未完成查询时显示 `未查询`。

时间为北京时间，审计明细显示到分钟，包含时间、源 IP、IP归属地、入口和目标网站五列。流量汇总为本月累计值。默认可查询最近 7 天的明细，数据库内最多保留 14 天，更早的数据已归档，不会出现在查询结果中。详见 [数据口径](../docs/data.md)。

## 连接与权限检查

`verify.py` 读取本地私有文件 `client/connection.json`，使用只读账号逐项验证：应可查询的表和视图能否正常查询；写入数据、修改表结构、读取系统账号表是否均被拒绝。该脚本会实际连接数据库，须在获得授权后运行：

```powershell
python client/verify.py --database <地区库名>
python client/verify.py --require-tiers
```

私有连接文件不随仓库提供，密码不应出现在日志、截图或提交记录中。`Start-Tunnel.ps1`、`Stop-Tunnel.ps1` 和 `tunnel.mjs` 是早期通过 SSH 隧道连接时使用的工具，当前采用直连方式，无需运行。
