# 最终运行时收口报告

日期：2026-09-19

本轮只完成“独立规则 → 聚合规则 → 客户端实际加载”链路的最终闭环，以及四份配置的日本策略组命名统一。没有重新设计架构，没有重做上游审计，没有修改任何 DNS 参数、TUN、sniffer、节点、订阅、筛选器、端口等与本任务无关的配置。

## 1. Crypto 聚合原来漏了什么

第三轮审计更新了多个独立 Crypto 规则，但聚合规则 `Crypto/Crypto.yaml` 没有重新同步。经对 48 个独立 Crypto 成员逐一比对（Mihomo 与 Egern 两侧），确认只遗漏 2 条：

- `etherscan.com`（独立规则 Etherscan 已在第三轮补入，聚合遗漏）
- `toncenter.com`（独立规则 TON 已在第三轮补入，聚合遗漏）

`mexc.co`、`mexcsensors.com` 在第三轮时已随 category-cryptocurrency 主列表进入聚合，本次确认已在。

## 2. 实际补入的规则

`Ruleset/Mihomo/Crypto/Crypto.yaml` 与 `Ruleset/Egern/Crypto/Crypto.yaml` 各补入 2 条（共 4 行 diff）：

- `DOMAIN-SUFFIX,etherscan.com`（Egern 侧 `domain_suffix_set: etherscan.com`）
- `DOMAIN-SUFFIX,toncenter.com`（Egern 侧 `domain_suffix_set: toncenter.com`）

聚合后 Mihomo Crypto 共 304 条，与 Egern Crypto 语义完全一致（逐条比对 0 差异）。没有删除任何独立文件，没有把 Finance/Shopping/Technology 内容混入。

## 3. Finance / PaymentCN 是否有遗漏

- Finance 聚合：MastercardCN、N26、PayPal、Wise 四个成员的每一条规则都已包含在 `Finance/Finance.yaml` 中，无遗漏，未做修改。
- PaymentCN：是独立加载的规则集（客户端直接 `RULE-SET,PaymentCN,DIRECT`），不参与 Finance 聚合；Mihomo 与 Egern 版本各 50 条，语义完全一致。8 个历史回归域名（tenpay.com、wechatpay.com、globaltenpay.com、doupay.com、jdpay.com、jdpaydns.com、wangyin.com、chinabank.com.cn）全部确认存在。

## 4. 聚合一致性检查

扩展了现有 `scripts/check.py`（没有新建框架）：

- 用一份简单可读的成员清单 `AGGREGATES` 定义 Crypto（48 个成员）与 Finance（4 个成员）的聚合关系；PaymentCN 作为独立加载的规则集，其 Mihomo/Egern 等价性由同脚本的双格式比对思路覆盖。
- 检查内容：每个成员文件的每条规则必须出现在聚合中（成员新增而聚合漏掉时检查失败）；聚合内无完全重复条目（沿用原有重复检查）。
- 验证过该检查确实有效：补入 etherscan.com/toncenter.com 之前运行即报告 4 条 AGGREGATE-MISSING，补齐后通过。

## 5. Ash（FlClash）：JP → 日本

- 策略组定义 `- name: JP` 改为 `- name: 日本`。
- 2 处策略组引用（Public network、流媒体）由 `- JP` 改为 `- 日本`。
- Finance、Crypto 两组原本引用的是 `日本`，属历史悬空引用（原配置引用了不存在的组名），改名后自动恢复为有效引用，无需额外改动。

## 6. 吹雪（FlClash）：JP → 日本

- 策略组定义 `- name: JP` 改为 `- name: 日本`。
- 3 处策略组引用（Public network、Google下载、流媒体）由 `- JP` 改为 `- 日本`。
- Finance、Crypto 两组同样因历史悬空引用自动修复。

## 7. Egern：JP → 日本

- 策略组定义 `name: JP` 改为 `name: 日本`。
- 4 处 policy 引用（Public network、Finance、Crypto、Streaming）由 `- JP` 改为 `- 日本`。

## 8. Clash Party 为什么不需要重命名

Clash Party 的策略组定义和所有引用早已统一使用 `日本`，本次仅复核确认一致，0 修改。

四份配置最终状态：Ash＝日本、Clash Party＝日本、Egern＝日本、吹雪＝日本。已用脚本确认：无任何残留的 `- JP` 策略组引用、无 `,JP` 规则目标、节点筛选正则中的 `\bJP\b|Japan|JPN` 全部原样保留（每份 3 处 filter 未动）。

## 9. PaymentCN 删除的重复手写规则

Ash、Clash Party、吹雪三份配置各自删除了 `RULE-SET,PaymentCN,DIRECT` 之后重复的 8 条手写规则（tenpay.com、wechatpay.com、globaltenpay.com、doupay.com、jdpay.com、jdpaydns.com、wangyin.com、chinabank.com.cn 的 DOMAIN-SUFFIX 直连规则），每份仅保留一行 `RULE-SET,PaymentCN,DIRECT`。这 8 个域名已逐一确认存在于 PaymentCN 规则集中，删除后路由结果不变。Egern 本来就只引用 PaymentCN 规则集，无需修改。fake-ip-filter 中的同名域名属于 DNS 配置，未触碰。

## 10. Egern DNS 三个第三方依赖的处理

结论：**保留，不改**。

- DNS `forward` 的 `proxy_rule_set` 与代理规则段的 `rule_set` 是两种不同的加载机制。仓库中的 Egern 规则文件是为后者设计的原生 YAML 格式（如 `Ruleset/Egern/Apple/Apple_All.yaml` 仅含 domain_set/domain_suffix_set）。
- 三个依赖中，`Apple_All.list` 尚可找到本地近似替代，但 `ChinaMaxNoIP_Domain.list`（约 11 万条域名后缀）与 `ChinaMaxNoIP.list`（含 USER-AGENT、PROCESS-NAME 等类型）在本仓库中没有等价物；把 11 万条域名复制进本仓库等于自己接管一个每日更新的上游项目，与“不重新设计架构”的原则冲突。
- 在没有官方文档明确 `proxy_rule_set` 接受 Egern 原生 YAML 的前提下强行替换，有破坏 DNS 分流（国内外域名解析走向）的风险。正确性优先，故保留这三个 blackmatrix7 运行时依赖，并在本节明确说明。

## 11. 运行时规则依赖现状

- 分流规则（rules/rule-providers）：Ash 126 条、吹雪 126 条、Clash Party 135 条引用全部指向 `zhbcn/Rules`，零第三方分流规则依赖。
- Egern：代理规则段全部指向 `zhbcn/Rules`；仅 DNS forward 段保留上述 3 个 blackmatrix7 列表（原因见第 10 节）。
- 其余第三方 URL 均为本任务禁止修改的基础设施：节点订阅 token、GeoIP/ASN 数据库、Egern 模块与 Sub-Store 配置、图标等。

## 12. 测试结果

- Python 单元测试：6/6 通过。
- `scripts/check.py`（含新聚合检查）：402 个规则文件 + 4 份客户端配置全部通过（YAML 可解析、无重复条目、聚合无遗漏、所有 zhbcn/Rules URL 存在）。
- Mihomo↔Egern 语义一致性：Crypto（304 条）、Finance（742 条）、PaymentCN（50 条）三对聚合 0 差异。
- 策略组引用检查：四份配置均无悬空地区组引用，`日本` 组均存在。
- 重点域名 `etherscan.com`、`toncenter.com`、`mexc.co`、`mexcsensors.com` 均已确认存在于客户端实际加载的 Crypto 聚合规则中。
- `git diff --check` 无空白错误；规则仓库 diff 仅 4 行新增 + check.py 扩展，无范围外修改。

## 13. 最终 commit

`50ddac4` — `fix: sync aggregate rules and runtime configs`，已推送到 `origin/main`（远端 SHA 已验证一致，raw URL 抽查通过）。
