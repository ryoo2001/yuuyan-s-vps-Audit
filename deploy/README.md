# 发布工具

本目录包含发布包生成器和 systemd 服务模板，不提供一键安装包。操作生产机器前，应先在现场核对配置，再按 [运维说明](../docs/operations.md) 和 [分级校验](../docs/validation.md) 执行。

## 日常更新：`update.py`

为单台采集机器生成仅包含改动文件的发布包，此步骤不连接服务器：

```powershell
python deploy/update.py <主机名> --changed audit.py --emit deploy/update-<主机名>.json --manifest deploy/update-<主机名>.manifest.json
```

`<主机名>` 对应 `config/<主机名>.json`，使用前应确认目标机器的实际角色。默认不覆盖机器上的配置，确需修改配置时才加 `--include-config`。

生成后应审查目标机器、文件哈希、需重启的服务及需执行的命令，先在单台机器上试运行，确认无误后再继续。生成的文件仅为待执行的计划，不代表部署已经完成。

## 文件说明

| 文件 | 用途 |
|---|---|
| `update.py` | 生成采集端的增量发布包 |
| `call.mjs` | 调用本地 ops_mcp 执行发布包，会在目标机器上实际执行 |
| `*.service`、`*.timer`、`*.conf` | 各角色的服务模板，需按需选用并核对 |
| `build.py` | 早期的全量生成方式；`--update` 会覆盖配置并重启服务 |
| `central.py`、`rename_db.py` 及其他迁移脚本 | 建库或迁移时一次性使用的脚本，不应用于修复生产数据库 |
| `deliver.mjs`、`client-check.py` | 交付账号凭据或进行在线检查，会连接服务器 |

`call.mjs` 依赖本机已配置的 ops_mcp 环境，仓库不提供主机列表和凭据。历史生成的 JSON 发布包可能包含旧版代码和敏感信息，不应提交、批量打印或直接重新执行。

部署时仅更新本次所需的组件，不重建镜像，不重启全部服务。验收后清理本次产生的临时回滚备份，正式的归档文件予以保留。
