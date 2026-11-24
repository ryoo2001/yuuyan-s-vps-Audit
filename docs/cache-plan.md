# 中心 48 小时热数据与 legacy-host 远端读取方案

状态：2026-11-23 起按本方案实施，主体已上线（见第 11 节，含与设计的差异和暂缓项）。用户决定以本方案取代原"热 3–7 天、在线 14 天"策略。第 1–10 节保留为设计记录。

## 1. 现场约束（2026-11-23 实测）

| 项目 | 数值 | 影响 |
|---|---|---|
| center-host 本机盘 fsync | 中位 0.41 ms | 热数据和全部写入放本机 |
| boost→tennet NFS fsync | 中位 5.7 ms | 不适合承载 InnoDB 写入 |
| tennet→boost 读带宽 | 约 2.4 MB/s（256 MB 直读 113.9 s） | 远端只能按需读取小块，不能扫表 |
| boost→tennet 写带宽 | 预热复制 2.5 GB 用时不到 4 分钟 | 归档上传不是瓶颈 |
| region-a 最近 48 h | samples 65,123 行；按小时聚合 7,408 组，按日聚合 3,032 组 | 小时级聚合表很小 |
| region-a connection_state | 48 h 内 49,847 行，全表 306,494 行（约 16%） | 审计明细只扫 48 h，扫描量约降到原来的 1/6 |
| 四张大表（visits、samples、connection_state、connection_rates） | 约占三库 2.4 GB 的 90% 以上 | 只需迁出这四类表 |

数据目录目前在 NFS 上，属于临时状态。本方案的前提是先把数据目录迁回本机盘。

## 2. 分层

| 层 | 位置 | 内容 | 读取方式 |
|---|---|---|---|
| 热 | boost 本机 MariaDB | 四张大表最近 48 h 原始事实；wire_samples、peers、entry_routes 等小表按原规则保留 | 五个中文视图直接读 |
| 聚合缓存 | boost 本机 MariaDB | `traffic_monthly`（已有）、新增 `traffic_hourly`、`ip_geo`（已有） | 视图和 summary 直接读，不访问远端 |
| 远端 | legacy-host（现有 NFS 冷档案目录） | 超过 48 h 的原始事实，按北京时间日分块，月底封包 | 按需拉取到本机读取缓存 |
| 读取缓存 | boost 本机独立库 `audit_cache` | 最近拉取过的日分块 | 工具和 `历史明细` 视图读取 |

不采用的方案：

- **InnoDB 表空间放 NFS。** hard 挂载一卡，整个 mariadbd 都会挂起，而且查询会受 2.4 MB/s 限制。
- **tennet 上另起 MariaDB，用 FEDERATEDX 联查。** 需要新开端口；远端变慢会拖住中心查询；条件下推也不可靠。
- **按查询结果缓存。** 新数据一到就失效，命中率低。聚合层用递增方式维护，始终是最新的。

## 3. 递增聚合（统计类查询不读远端）

### 3.1 流量汇总（月累计）

沿用现有机制，不需要改动：

- `traffic_monthly` 由 samples 和 traffic_rollup 上的触发器按差量递增维护。
- 归档删除走 monthbook 的抑制机制，不会扣减月累计。
- 已迁出部分的月累计写在 `traffic_calendar`。

热窗口缩到 48 h 后，月累计仍从 1 日累计到最新样本，不读远端。

### 3.2 新增 `traffic_hourly`（任意时间窗汇总）

MCP `traffic_audit_summary` 和 `query.py summary` 支持最长 31 天的任意窗口。现在它们读原始表；热窗口缩到 48 h 后，早于 48 h 的部分必须改从聚合表读。

- **结构**：每个命名空间一张，主键 `(hour_start, source_ip, node, site)`。字段为 `upload_bytes`、`download_bytes`、`fact_rows`、`visit_events`，`hour_start` 取 UTC 整点。
- **维护方式**：复用 `storage.py` 生成 `traffic_monthly` 触发器的代码，只把月份键换成小时键。
  - samples 和 traffic_rollup 的 INSERT 加差量，UPDATE 先减旧值再加新值。
  - 归档删除同样被 monthbook 抑制，不扣减。
  - visits 的 INSERT 和 DELETE 维护 `visit_events`。
  - 写入是逐行递增的，不需要定时全量重算。
- **规模估算**：region-a 每天约 3,700 组。保留 62 天约 23 万行，约 30 MB；hk、us 更小。
- **保留**：滚动 62 天，覆盖"本月加上月"以及 31 天窗口。用普通 DELETE 清理，清理不经过归档保护，也不影响月累计。
- **读取规则**：
  - 窗口落在 48 h 内：读原始表，与现在一致，精度到分钟。
  - 窗口早于 48 h：读 `traffic_hourly`，边界精度为 1 小时。返回 `precision=hour`，并说明边界取整。
  - 窗口跨越两者：两部分合并，以热层起点为界，避免重复计数。
- **一次性回填**：上线时对当前在线的 14 天原始数据按小时聚合写入一次。更早的数据只有月累计，没有小时粒度；早于回填起点的窗口会返回 `hourly_not_available_before`。

### 3.3 入口流量汇总

wire_samples 是分钟级桶，region-a 14 天约 29 MB，是小表。它在本机保留 7 天，不迁出，视图窗口不变。

## 4. 审计明细与访问记录

- 两个视图的热窗口从 7 天（`unix_timestamp() - 604800`）改为 48 h（`172800`），5 秒去重和列契约不变。
- 扫描量约降到原来的 1/6；放回本机盘后，明细全量和计数查询预计会快于迁移前，需实测确认。
- 早于 48 h 的明细不再出现在这两个视图里，改由第 6 节的按需拉取提供。

## 5. 远端分块与迁出流程

沿用 `archive.py` 已验收的流程：写压缩文件、fsync、重读核对行数和校验和、在同一事务里写 `archive_receipts` 并删除库内行。只改以下几点：

- 四张大表的截止点从 14 天改为 48 h；wire_samples 及其他小表的截止点保持不变。
- 分块粒度固定为"北京时间日 × 表 × 命名空间"，便于按天拉取。月底封包逻辑不变。
- 估算 region-a 每天原始数据约 38 MB（四张大表数据量 533 MB ÷ 14 天），压缩后约 5–8 MB。按 2.4 MB/s 计，拉取一天约 2–4 秒。需实测确认。
- 首次切换时，48 h 至 14 天之间约 12 天的积压会分批迁出。每轮受现有 20 秒预算限制，不会长时间锁表。
- 迁出完成后，用 `ALTER TABLE ... FORCE`（在线重建，一次一张表）回收表空间。预计数据目录从 2.4 GB 降到约 0.5 GB，需实测。

## 6. 按需拉取与读取缓存（`audit_cache`）

- **缓存单位**：日分块，键为 `(database, namespace, table, day, chunk_sha256)`。
- **拉取步骤**：
  1. 从 NFS 读取分块。
  2. 按 `archive_receipts` 核对 SHA-256 和行数。
  3. 载入本机库 `audit_cache` 中对应的分区表，并记录 `cache_index`（大小、载入时间、最近访问时间）。
- **一致性**：分块内容不可变；迟到更正会重封分块，SHA-256 随之改变。读取前比对 receipt，不一致时丢弃缓存并重新拉取，因此不会读到过期数据。
- **淘汰**：按最近访问时间做 LRU，总量上限默认 300 MB，单块最长保留 7 天。只删除 `audit_cache` 里的副本，远端分块不动。
- **递增预取**：每天 00:10（北京时间）前一天的数据刚越过 48 h 迁出，同时把这一天写入缓存。"昨天之前一天"的明细因此命中率最高，也不额外读远端，因为这份数据是刚写出的本机副本。
- **访问入口**：
  - `query.py details` 和 MCP `traffic_audit_details` 增加 `--from/--to`。窗口早于 48 h 时自动拉取缺失的日分块，返回 `source_tier=cache|remote`，并附拉取用时。
  - 新视图 `历史明细`：列与 `审计明细` 相同，只展示已在缓存中的日期，供 Navicat 等只读客户端使用。`audit_ro` 不能触发拉取；视图第一行说明当前覆盖的日期范围。
  - 单次请求最多拉取 7 天，超出时提示缩小范围，避免一次占用远端带宽过久。
- **故障隔离**：拉取使用独立进程，设置 30 秒超时。tennet 或 NFS 不可用只影响历史查询，返回 `remote_unavailable`，热层和写入不受影响。

## 7. 备份改到 term-c-host

- `backup.sh` 先在本机生成并校验 dump（逻辑不变），再通过 term-c-host 上已建好的受限账号 `auditbackup`（强制命令 `put <name> <bytes> <sha256>`）上传。接收端核对大小、SHA-256 和 zstd 完整性后才落盘。
- 上传成功后执行 `prune 2`，保留 2 份；不再写 tennet 的 `_backup/`。原有两份旧备份待新备份验证后再决定是否删除。
- 数据目录回到本机盘后，备份读取走本机盘，不再占用 tennet 链路。
- 每月做一次恢复演练，在 term-c-host 临时容器中执行，不影响生产。

## 8. 实施顺序

1. **数据目录迁回本机盘。** 需停库。瓶颈是从 NFS 读取全部约 2.5 GB，按 2.4 MB/s 估算约 17–20 分钟。publisher 积压的数据在恢复后补传，上次切换后 `missing_rows=0`。
2. **本地代码。** `tier_policy`、`archive.py`（按表截止点、日分块）、`storage.py`/`region.py`（小时表 DDL 和触发器）、`detail_view.py` 及三库视图、`query.py`/`hk_query_core.py`、新增 `warm_cache.py`、`backup.sh`；补 MySQL 夹具测试和 ops_mcp schema。
3. **隔离测试库验证。** 验证小时表递增和归档抑制、跨层 summary 不重复计数、拉取校验和 LRU。
4. **生产部署。** 依次建小时表并回填、替换视图、切换截止点并分批迁出、重建表回收空间、切换备份。
5. **验收。** 固定时间窗下 summary 与原始数据对账，明细查询耗时，历史拉取耗时，term-c-host 备份可恢复。
6. **文档。** 更新 `AGENTS.md` 用户决策、`storage.md`、`data.md`、`operations.md`、`state.md`、`baseline.json`。

## 9. 待用户确认

- 早于 48 h 的明细，在数据库客户端里通过 `历史明细` 读取已缓存的日期，由查询工具触发拉取。这种方式是否可以？
- 第 1 步需要再停库约 20 分钟。
- 入口流量汇总保持 7 天本机保留。
- `traffic_hourly` 保留 62 天；更早的时间窗只有月粒度。

## 10. 已知限制

- 小时表回填前已迁到冷档案的月份没有小时粒度。
- 远端带宽实测只有约 2.4 MB/s，大范围历史明细拉取会慢。
- tennet 仍是冷数据唯一副本所在地。term-c-host 上的备份是逻辑备份，只覆盖库内数据，不含远端分块。是否把冷档案也同步到 term-c-host，另行决定。

## 11. 实施状态（2026-11-23 至 11-24，UTC 实测）

已上线：

| 部分 | 实现 | 位置 |
|---|---|---|
| 热层截止点 | samples、visits、connection_state、connection_rates 保留 48 h；wire_samples、traffic_rollup 仍为 14 天 | `tier_policy.py`（`RAW_HOT_HOURS=48`、`RAW_HOT_TABLES`、`HOURLY_TOTALS_DAYS=62`） |
| 日分块迁出 | 每个北京时间日 × 表 × 命名空间一个 gzip JSONL；删除与 `archive_chunks` 登记同一事务 | `archive.py`，timer 每 5 分钟 `run --budget 20` |
| `traffic_hourly` | 每命名空间一张，触发器递增，保留 62 天 | `hourly.py`、`region.py` |
| summary 分层 | 边界取 `ceil((now-48h)/3600)*3600`；边界前读小时表，之后读原始表；连接数只统计原始部分；返回 `storage_window` 和说明 | `tier_summary.py`，region-a `query.py` 与 HK store reader 共用 |
| 历史明细 | `details --from/--to`（最长 7 天）；早于 48 h 的部分读冷分块，与原始行按时间合并，按 connection_id 和分钟会话键去重；返回 `history.source_tier`（cache/remote/unavailable/none） | `history_cache.py`、`hk_history.py`、`query.py` |
| MCP | `traffic_audit_details` 增加 `from`/`to`，仅中心可用；summary 描述改为 48 h + 小时表 | `D:\ops_mcp\src\tools\audit\index.ts`，dist 已构建 |

与设计的差异：

- **读取缓存用 SQLite 日文件**，未建 MySQL 库 `audit_cache`。路径 `/var/lib/traffic-central/history-cache/<db>/<北京日>.sqlite`，仅 root 可写。按分块 digest 递增载入；只读取调用者 MySQL 一致性快照里 `archive_chunks` 列出的分块，迁出过程中的行不会重复计数。载入前核对 SHA-256、文件头和行数。拉取在子进程内进行，30 秒超时。淘汰为 LRU，总量 300 MB，闲置 7 天删除；目前在每次窗口查询后执行。
- **历史明细的路由和归属地**用当前的 `entry_routes` 和 `ip_geo` 补，不是事发时的路由。响应带 `history_details_from_cold_chunks_with_current_routes_and_locations` 说明。
- **默认明细不变。** 不带窗口时 region-a 仍读 48 h 原始表，HK 仍读 `审计明细` 视图；两者输出与改动前逐行一致。

- **明细视图的执行形式（11-24 修订）。** 单命名空间视图的相关反连接在 48 h 表上每个外层行扫大量索引项，全量计数超过一分钟并占满单核；改为只对 `by_detail` 覆盖索引上 48 h 内的行做窗口排名，计数约 0.3 秒，行与顺序和原定义一致。`by_session` 辅助索引已取消。新区域经 `region.py` 仍只建 `by_detail`。详见 state.md 最上面一节。

暂缓（未实施）：

- **`历史明细` 视图。** 缓存不在 MySQL 中，`audit_ro` 无法读取，也不能触发拉取。数据库客户端里只能看到 48 h 内的明细，历史明细通过 MCP 或 `query.py details --from/--to` 读取。
- **每日递增预取**和独立的缓存淘汰 timer。
- **表空间回收。** 积压迁完后，再逐表执行 `ALTER TABLE ... FORCE`，并重新做小时表校验。

验收记录（2026-11-23）：

- summary：region-a 和 HK 都比对了三种窗口，即 48 h 内、整段早于 48 h（11-20T18Z 至 11-21T04Z）和跨边界窗口。字节数和事件数与原始数据一致，域名过滤结果一致。
- 历史明细：region-a 11-10 06–09 时首次拉取 36 块，约 1 MB，耗时 0.64 s；再次查询命中缓存，载入行数与 `archive_chunks` 登记一致（17,970 行）。HK 11-12 首次拉取 25 块，耗时 0.52 s。超过 7 天的窗口返回错误。
- 这些结果只说明上述固定时间窗的情况，不代表数据完整或可用于计费。
