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

2026-11-15 以上次完整核对（2026-11-12）的固定版本为基线，核实最新提交及公开上游差异；本次仅更新 Mihomo / Egern，按用户要求暂不更新 Loon、Quantumult X、Stash 资源和客户端配置。未读取节点订阅。

| 上游 | 当前核对的固定提交 |
|---|---|
| v2fly/domain-list-community | `777d056afe68b2643c1ef15f80e7bde3dfa149b1` |
| blackmatrix7/ios_rule_script | `0b6897dc17e0c513d25449c935a9694818e32f0c` |
| SukkaLab/ruleset.skk.moe（官方构建输出，`List/`） | `c852f05fe00181871397037e8dba1442b0d7134f` |
| QingRex/LoonKissSurge | `913ec005f544221e6c56a7d0ecec81c4b3b914bb` |

- V2Fly 相对 `2b7ae3222f79e58e323a6b1c30c6618821068963` 仅增加 `greatfire` 的 `manyvoices.news`，现有 Mihomo / Egern `Global_Domain` 已覆盖，不重复追加。blackmatrix7、QingRex 的版本未变。
- Sukka 构建相对 `472dc569b0788a83202fb2042845dd4c341a47c3` 有更新；下载两个固定版本中当前引用的六份文件，按既有平台转换边界比较 Reject、RejectDrop、RejectNoDrop、LAN 四个集合。仅 RejectDrop 的 IP 集合变化：移除 `51.89.187.141/32`，增加 `172.255.6.254/32`，两端同步。其他变化的 CDN、测速、AI IP、国内域名/IP 及 domainset 拦截资源不在当前这些集合的引用范围，不扩大接入范围。
- 本次仍保留 RejectDrop / RejectNoDrop 的禁用状态，不修改客户端配置。Quantumult X / Stash 的 RejectDrop 派生资源暂保留旧 IP，因此全格式生成一致性检查预期报告这两处过期；后续恢复更新时运行原有生成器，不手改派生文件。
- 上次完整核对覆盖 228 个 Mihomo 维护资源中的 180 个上游关联资源；39 个纯自定义、6 个官方/人工精选资源和 3 个旧国际兼容子集保持既有范围。新增的 NVIDIA_Direct 保留已审阅内容，本次不重新构建全部资源。
- 保留 Amazon/Ozon 已被现有后缀覆盖的条目处理、`Tencent_Domain` 对公共后缀 `in.th` 的排除，以及 HTTPDNS `118.89.204.0/23` 的规范化及 `no-resolve`。Anthropic 入站 IP、ChinaAI/cn 的已确认 custom 和代理例外不变。
- 本记录证明公开上游核对及本地资源维护，不代表资源已发布、客户端实际加载或业务连通性验证。

本文件只做简要归属和快照说明，不替代各上游仓库中的完整许可证文本。
