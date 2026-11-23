# socks5中转统计

本指南用于部署“入口机器解析真实用户、Socks5 机器负责出站”的审计链路。典型结构如下：

```text
真实用户 → term-d:8443 AnyTLS →
  ├─ DIRECT → term-d 直出
  └─ egress-d:1080 Socks5 → egress-d 出站
```

## 口径

- 真实用户 IP 取入口机 Mihomo 控制器的 `metadata.sourceIP`。
- 出口机器取控制器连接的 `chains`。`DIRECT` 映射为入口机，Socks5 节点映射为出口机。访问日志只取 `using` 之后的出站名，`match` 后面的规则名不参与判断；`组名[节点]` 写法先按节点名匹配。
- `default_egress` 只用于控制器没有报告任何链路的连接。报告了链路但 `egress_by_chain` 里没有对应项时，出口机器留空，链名写入健康文件的 `unmapped_egress_routes`，并产生 `unmapped_egress_route` 告警，不会默认记成入口机。`REJECT`、`REJECT-DROP` 表示连接被规则拒绝，出口机器留空，但不告警。
- 控制器来源只接受全球单播地址。回环、内网、链路本地、多播、文档和 `198.18.0.0/15` 地址不会作为用户源 IP。
- 该入站必须由客户端直连。如果密文指纹给出的源地址与控制器 `sourceIP` 不同，说明前面多了一层转发，两个地址都不写入，归属依据记为 `source_conflict`，健康文件计数 `controller_source_conflicts` 并产生 `controller_source_conflict` 告警。与控制器一致的迟到指纹不会改写出口机器。
- 出口 Socks5 机看到的源地址是入口机地址。该地址只能作为出口侧遥测，不能写入用户源 IP。
- 中心用户视图读取入口机的权威分区。Socks5 机使用独立命名空间保留原始事实和同步状态。
- 历史“未识别”记录没有证据时不回填。新连接必须在完整经过入口机控制器采样后再验收。

## 部署前确认

先通过 ops_mcp 实探两台机器和中心机，确认以下内容。

| 角色 | 必须确认 |
|---|---|
| 入口机 | Mihomo 控制器为 loopback，AnyTLS 入站端口、网卡和链路名称，出口链名称 |
| Socks5 出口机 | Socks5 入站端口、网卡、控制器类型，入口机到该端口的连接源地址 |
| 中心机 | 目标库、命名空间、上传账号来源限制、只读视图权限 |

不要把入口机到 Socks5 出口机的连接源地址配置成用户源 IP。不要为了安装审计脚本重启 Mihomo、隧道、防火墙或数据库。

## 入口机配置

在入口机终端配置中加入显式的控制器源地址规则。以下示例对应 AnyTLS `8443`。

```json
{
  "inbound_ports": [8443],
  "inbound_types": {"8443": ["AnyTLS"]},
  "controller_source_ip": {
    "8443": {
      "types": ["AnyTLS"],
      "egress_by_chain": {
        "DIRECT": "term-d",
        "egress-d-socks5": "egress-d"
      },
      "default_egress": "term-d",
      "trust_unmatched_logs": true
    }
  },
  "egress_nodes": {
    "term-d-direct": "term-d",
    "term-d": "term-d",
    "egress-d-direct": "egress-d",
    "egress-d": "egress-d"
  }
}
```

`controller_source_ip` 只用于已明确核验的入口协议和端口。`egress_by_chain` 必须使用 Mihomo 实际返回的链名称。配置变更后只重启 `traffic-audit.service`，并检查配置文件权限为 `600`。

入口机应同时运行 terminal 和本机 direct edge。两者都抓取客户端进入的端口，direct edge 将指纹送回本机 terminal。控制器源地址规则负责补足短连接和指纹无法跨出入口机的 Socks5 路径。

## Socks5 出口机配置

出口机可以运行 terminal、本机 direct edge 和独立 publisher。它的原始事实必须写入独立命名空间，例如 `egd_`。

```json
{
  "mode": "terminal",
  "node": "egress-d",
  "inbound_ports": [1080],
  "inbound_types": {"1080": ["Socks5"]},
  "captures": [
    {"interface": "ens7", "tcp_ports": [1080], "udp_ports": [1080]}
  ],
  "peers": {
    "egress-d-direct": {
      "auth_file": "/etc/traffic-audit/egress-d-direct-auth.toml",
      "tcp_ports": [1080],
      "udp_ports": [1080]
    }
  }
}
```

出口机 publisher 使用独立 writer、publisher 名称和表前缀。只授予该前缀物理表的 DML 权限，例如 `us.egd_*`。不要把它写入默认分区，也不要让出口机的 `203.0.113.114` 一类上游地址进入用户源 IP 字段。

## 中心数据结构

为新区域建立统一 schema v2，再创建出口映射表。US 使用的映射表为 `us.us_egress_nodes`，字段包括 `audit_node`、`egress_node`、`route_type` 和 `upstream_node`。

用户视图使用以下列。

```text
审计明细      时间 | 源 IP | IP归属地 | 出口机器 | 目标网站
流量汇总      时间 | 源 IP | IP归属地 | 出口机器 | 目标网站 | 流量统计
入口流量汇总  时间 | 源 IP | 出口机器 | 传输协议 | 上行线路流量 | 下行线路流量 | 分钟平均上传速率 | 分钟平均下载速率
访问记录      时间 | 源 IP | 出口机器 | 目标网站 | 归属依据
同步状态      采集节点 | 最后入库时间 | 距上次同步秒 | 确认位置 | 单批最大缺失数 | 统计说明
```

中心用户视图只合并真实用户源所在的权威分区。出口机命名空间保留原始表和同步状态，便于核对出站流量，不直接参与用户源 IP 归属。

## 上线验收

按单台机器执行，不直接重放历史发布 JSON。

```powershell
python tools/check.py
python tools/validate.py --business collector --changed audit.py --changed presentation.py --changed query.py --run
python -m unittest discover -s tests -v
```

现场至少完成以下检查。

1. 入口机健康文件中的 `mihomo_controller_available` 为真。
2. 新采样的 `unresolved_connections` 为零，或对每个未识别连接记录具体原因。
3. 中心默认分区最近窗口中 `source_ip` 非空，且 `node` 按链路显示 `term-d` 或 `egress-d`。
4. 中心用户视图中不存在出口机地址作为用户源 IP。
5. 入口 publisher 和 Socks5 publisher 的 `last_error` 为空，`missing_rows=0`，确认位置持续前进。
6. `audit_ro` 能读五个中文视图，不能读取原始事实表。

推荐使用一条直出连接和一条经过 Socks5 的连接分别验收。网站由入口机 Mihomo 控制器解析，IP 由入口机控制器直接提供，中心归属地任务再处理 `ip_geo`。

## 故障定位

| 现象 | 处理顺序 |
|---|---|
| 显示 `203.0.113.114` | 检查中心是否把出口机命名空间并入用户视图，检查入口机 `controller_source_ip` 是否启用 |
| Socks5 有网站但用户 IP 为空 | 检查入口机控制器连接是否采样，检查 `chains` 名称和入口机审计服务日志 |
| 直出有 IP、Socks5 无 IP | 确认入口机而不是出口机是权威采集端 |
| 出口机器为空、健康文件有 `unmapped_egress_route` | 按 `unmapped_egress_routes` 中的实际链名补充 `egress_by_chain`，只重启 `traffic-audit.service`；已写入的空出口不回填 |
| 归属依据为 `source_conflict` | 入口前可能新增了 SNAT 或四层转发。先确认链路，再决定改用入口探针指纹或撤下 `controller_source_ip`，不要手工填源 IP |
| 所有记录未识别 | 检查入口机控制器、AnyTLS 端口、`traffic-audit-direct-edge.service` 和新连接是否在服务启动后建立 |
| publisher 有积压 | 先检查中心 TCP/3306、writer 账号来源限制和前缀表权限，不清空队列、不重置 epoch |

相关实现见 [audit.py](../audit.py)、[term-d 配置示例](../config/term-d.json) 和 [US 中心视图生成器](../central/us_views.py)。
