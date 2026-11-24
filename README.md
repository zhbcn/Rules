# Rules

个人代理分流规则库（公开仓库 `zhbcn/Rules`），采用「上游同步 → 增量补丁/自建服务 → 稳定 Bundle 聚合 → 五端原生编译产物」四阶段单向构建架构。

技术规范见 [docs/client-specs.md](docs/client-specs.md)。设备出口、DNS、节点订阅与私密客户端配置由独立的本地私密配置仓库维护，本仓库不保存任何私密配置、凭据或反向依赖。

## 目录结构

| 路径 | 用途 |
| :--- | :--- |
| `docs/client-specs.md` | 五端官方语法、最优格式、DNS 边界与不支持项技术基线 |
| `sources.json` | 上游仓库锁定的 commit SHA 与 172 份上游规则来源映射 |
| `upstream/` | 只读规范化上游源（`zhbcn-rules/v1`），已剥离平台专属 `PROCESS-*` |
| `custom/services/` | 53 份自建与精选服务源（`zhbcn-rules/v1`），涵盖 Crypto、Apple/MS/Google 基础设施和补充域名等 |
| `custom/patches/` | 面向特定源的 `+` / `-` 增量补丁（`zhbcn-patch/v1`），上游同步不覆盖 |
| `bundles.json` | 22 个稳定对外 Bundle 定义（本仓库与下游配置仓库之间的唯一接口契约） |
| `dist/` | 由 `scripts/build.py` 自动编译的五端原生发布产物 + `manifest.json` + `build-report.json` |
| `scripts/` | `build.py`（编译）、`check.py`（自检）、`sync_upstream.py`（上游同步，内部复用 `convert_v2fly.py`）、`probe_ai_direct.py`（手动直连探测，清单 `ai_services.json`） |

### `dist/` 五端产物布局

| 客户端 | 产物路径 | 格式说明 |
| :--- | :--- | :--- |
| **Mihomo**（Clash Verge Rev / FlClash） | `dist/mihomo-stash/<id>_domain.mrs`、`dist/mihomo-stash/<id>_ipcidr.mrs`、`dist/mihomo-classical/<id>_classical.yaml` | 域名与 IP 编译为二进制 `.mrs`；少量无法入 `.mrs` 的规则输出极小 `classical` YAML |
| **Stash**（3.6+） | 复用 `dist/mihomo-stash/*.mrs` + `dist/stash-classical/<id>_classical.list` | 与 Mihomo 共享同一套 `.mrs` 二进制 + 极小 `classical` 纯文本 |
| **Egern** | `dist/egern/<id>.yaml`（含 `dns_bound` 纯域名分体 `dist/egern/<id>_domain.yaml`） | 原生 `*_set` 结构化 YAML；含 IP/ASN 的文件顶层带 `no_resolve: true` |
| **Loon**（Build 1008+） | `dist/loon/<id>.list` + `dist/loon/aigc_stun.list` | 无策略原生 `.list`（IP/ASN 带 `,no-resolve`）；`aigc_stun.list` 预展平 AI STUN 逻辑规则 |
| **Quantumult X**（1.5.5+） | `dist/quantumultx/<id>.list` | 原生三段式 `type,value,proxy`（客户端通过 `force-policy` + `opt-parser=false` 覆写策略） |

## 常用命令

从仓库根目录使用全局 Python 3.14（先执行 `python -m pip install -r requirements.txt` 安装 PyYAML）：

```powershell
# 1. 编译 22 个 Bundle 到五端 dist/（自动探测本机 verge-mihomo.exe / mihomo）
python scripts/build.py
python scripts/build.py --check

# 2. 运行纯仓库自检与单元测试（零私密配置耦合）
python scripts/check.py
python -m unittest discover -s tests

# 3. 按需同步上游（支持远程锁定 commit 拉取或本地快照目录）
python scripts/sync_upstream.py --update-commits --remote
python scripts/sync_upstream.py --v2fly-data <path> --bm7-dir <path>
```

## AI 与 NVIDIA 边界

- **AI 规则**：海外 AI 归入 `aigc` Bundle；国产 AI 归入 `china_ai` Bundle，并在 `bundles.json` 中显式通过 `exclude_domains` 排除需代理的国际子域（如 `talkie-ai.com`、`coze.com`、`trae.ai` 等）。
- **NVIDIA 规则**：`nvidia_direct`（中国站与驱动下载直连子集）与 `nvidia_global`（全球余集）作为独立 Bundle 分别输出，客户端按 `nvidia_direct` → `nvidia_global` 顺序挂载。

## 直连探测工具

`scripts/probe_ai_direct.py` 为手动运行的 Windows 直连探测工具，通过 `IP_UNICAST_IF` 绑定物理网卡进行 AliDNS DoH 与 HTTPS 连通性核验，不触发机场订阅、不修改系统网络设置。
