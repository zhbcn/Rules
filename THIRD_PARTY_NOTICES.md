# 第三方来源说明

本项目将上游规则规范化到 `upstream/`，按 Bundle 编译为 `dist/` 下的 Mihomo（供 Clash Verge Rev 和 FlClash 使用）、Egern、Stash、Loon 与 Quantumult X 产物。以下列出主要上游及许可证。具体来源见 `sources.json` 的映射及规范源文件的 `source` 字段。

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
- 本项目仅提取域名/IP 条目及等价的域名逻辑条件，规范源保存为 `upstream/system/advertising.yaml` 和 `upstream/system/httpdns.yaml`，再编译为 `dist/` 下的对应产物。Quantumult X 的 `.list` 仅保留原生支持的条件，不包含上游脚本、重写或 MITM。

## 锁定的上游版本

以下版本与 `sources.json` 中的上游锁定记录一致。执行 `scripts/build.py` 会从规范源编译五端产物，生成的文件及格式适配记录分别见 `dist/manifest.json` 和 `dist/build-report.json`。

| 上游 | 锁定提交 |
|---|---|
| v2fly/domain-list-community | `777d056afe68b2643c1ef15f80e7bde3dfa149b1` |
| blackmatrix7/ios_rule_script | `0b6897dc17e0c513d25449c935a9694818e32f0c` |
| SukkaLab/ruleset.skk.moe（官方构建输出，`List/`） | `c852f05fe00181871397037e8dba1442b0d7134f` |
| QingRex/LoonKissSurge | `913ec005f544221e6c56a7d0ecec81c4b3b914bb` |

本文件只做简要归属和快照说明，不替代各上游仓库中的完整许可证文本。
