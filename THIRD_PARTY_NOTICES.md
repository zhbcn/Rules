# 第三方来源说明

本项目会把上游规则整理、转换并保存为自己的 Mihomo 与 Egern 文件。以下是主要上游及其许可证；具体规则来源仍以每个规则文件顶部的注释为准。

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
- 本项目仅提取域名/IP 条目及等价的域名逻辑条件，保存为 `System/Advertising.yaml`、`System/HTTPDNS.yaml` 配对文件；不包含上游脚本、重写或 MITM。

本文件只做简要归属说明，不替代各上游仓库中的完整许可证文本。
