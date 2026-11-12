# 第三方来源说明

本项目会把上游规则整理、转换并保存为自己的 Mihomo、Egern、Quantumult X 与 Stash 文件。以下是主要上游及其许可证；具体规则来源仍以每个规则文件顶部的注释为准。

## v2fly/domain-list-community

- 项目：https://github.com/v2fly/domain-list-community
- 许可证：MIT License
- 许可证原文：https://github.com/v2fly/domain-list-community/blob/master/LICENSE

## blackmatrix7/ios_rule_script

- 项目：https://github.com/blackmatrix7/ios_rule_script
- 许可证：GNU General Public License v2.0（GPL-2.0）
- 许可证原文：https://github.com/blackmatrix7/ios_rule_script/blob/master/LICENSE

## SukkaW/Surge（ruleset.skk.moe）

- 项目：https://github.com/SukkaW/Surge
- 许可证：GNU Affero General Public License v3.0（AGPL-3.0）
- 许可证原文：https://github.com/SukkaW/Surge/blob/master/LICENSE

## QingRex/LoonKissSurge 中的拦截规则

- 来源：https://github.com/QingRex/LoonKissSurge/tree/main/Surge/Beta
- 文件：`广告平台拦截器.beta.sgmodule`、`HTTPDNS拦截器.beta.sgmodule`。
- 上游标注作者：luestr；HTTPDNS 文件另标注 VirgilClyne。
- 本项目仅提取域名/IP 条目及等价的域名逻辑条件，保存为 `System/Advertising.yaml`、`System/HTTPDNS.yaml` 配对文件；Quantumult X 对应 `.list` 仅保留其原生支持的条件，不包含上游脚本、重写或 MITM。

## 当前已核对的上游快照

2026-11-12 下载以下固定提交的公开规则并比较已有资源；未读取节点订阅。版本指向实际下载内容，不以规则文件的注释日期推定版本。

| 上游 | 固定提交 |
|---|---|
| v2fly/domain-list-community | `2b7ae3222f79e58e323a6b1c30c6618821068963` |
| blackmatrix7/ios_rule_script | `0b6897dc17e0c513d25449c935a9694818e32f0c` |
| SukkaLab/ruleset.skk.moe（官方构建输出，`List/`） | `472dc569b0788a83202fb2042845dd4c341a47c3` |
| QingRex/LoonKissSurge | `913ec005f544221e6c56a7d0ecec81c4b3b914bb` |

Sukka 的源码说明来自 `SukkaW/Surge@d3b5d42081ae134e9ebf3efa74be58c14fc3ec9c`；实际转换使用上表构建输出，二者版本分别记录，不声称构建输出来自该源码提交。

- 228 个 Mihomo 维护资源中，180 个按其已有上游、筛选及聚合范围比较；39 个纯自定义、6 个官方/人工精选资源和 3 个旧国际兼容子集保持既有范围。Egern 配对及两个派生格式另由仓库检查核对。
- 未发现需要扩大或缩小有效域名/IP 覆盖的上游变化。Amazon/Ozon 中的 24 条精确主机或更具体后缀已被现有后缀覆盖，不追加重复条目；不扩大购物集合的服务范围。
- 保留 `Tencent_Domain` 对公共后缀 `in.th` 的明确排除，并以 Public Suffix List 重新核实；不将其恢复为腾讯直连范围。
- HTTPDNS 上游的 `118.89.204.198/23` 带主机位，继续规范化为等价的 `118.89.204.0/23`；保留 `no-resolve`。Anthropic 入站 IP、ChinaAI/cn 的已确认 custom 和代理例外保持。
- `sync_ai.py` 对本地快照实际同步及随后 `--check` 均为 36 个源输出、0 个变化。此记录证明所列公开上游的本地核对，不代表客户端实际加载或业务连通性验证。

本文件只做简要归属和快照说明，不替代各上游仓库中的完整许可证文本。
