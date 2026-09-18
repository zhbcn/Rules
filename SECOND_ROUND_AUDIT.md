# 第二轮语义审计报告

审计日期：2026-09-19

本轮只修正规则语义、转换脚本和来源说明，没有改变目录体系，也没有修改任何客户端配置、DNS、TUN、sniffer、节点或订阅。

## 1. PaymentCN 回归检查

重构前四份配置的支付规则均已与当前 `PaymentCN` 对比。8 个指定旧域名的结果如下：

| 域名 | 审计前 PaymentCN | 审计后 | 处理 |
| --- | --- | --- | --- |
| tenpay.com | 已有 | 已有 | 保留 |
| wechatpay.com | 缺失 | 已有 | 从原配置补回 |
| globaltenpay.com | 缺失 | 已有 | 从原配置补回 |
| doupay.com | 缺失 | 已有 | 从原配置补回 |
| jdpay.com | 已有 | 已有 | 保留 |
| jdpaydns.com | 已有 | 已有 | 保留 |
| wangyin.com | 缺失 | 已有 | 从原配置补回 |
| chinabank.com.cn | 已有 | 已有 | 保留 |

结论：发现并补回 4 个回归域名。PaymentCN 从 46 条增至 50 条，最终来源为 V2Fly 支付相关规则加原配置中已实际使用的合理补充。

## 2. Shopping scope 审计

### 已修正的公司级列表

| 规则 | 原条数 | 新条数 | 修正内容 |
| --- | ---: | ---: | --- |
| Amazon | 252 | 29 | 只保留 Amazon 商城国家站和购物静态资源；移除 AWS、CloudFront、IMDb、Kindle、Prime Video、Whole Foods、Alexa、Audible 等非购物服务 |
| Rakuten | 31 | 6 | 收窄为日本 Rakuten Ichiba；移除 Kobo、Viber、Viki、Rakuten TV、Rewards/Advertising 等非 Ichiba 服务 |
| BestBuy | 82 | 17 | 保留商城、商业采购、奖励、交易和静态资源；移除招聘、慈善、企业宣传及 Geek Squad 独立服务域名 |
| eBay | 363 | 38 | 保留 eBay 主要国家站、商城资产、eBay Motors/Stores；移除 Kijiji、Mobile.de、Qoo10、Terapeak 等并购或独立品牌以及企业宣传域名 |
| Ozon | 63 | 14 | 保留商城国家站、Express、Market 和内容域名；移除 Ozon Travel、Credit/Card、Tech/Dev、Courier、广告追踪等非购物域名 |

### 已检查但无需修改

- V2Fly 服务级且范围仍是购物：Costco、Coupang、Farfetch、Newegg、Shopee、Target、Walmart。
- 原自维护且内容与规则名一致：AliExpress、Allegro、ASOS、Etsy、Flipkart、iHerb、Lazada、MercadoLibre、Mercari、Noon、SHEIN、Temu、Wayfair、Zalando。

结论：26 个 Shopping 规则全部检查；修改 5 个，保留 21 个。没有为了增加数量扩大任何规则范围。

## 3. V2Fly affiliation 修复

`scripts/convert_v2fly.py` 现在会：

1. 扫描 `data/` 中所有直接域名规则并建立 `&target` 索引。
2. 把规则同时加入原列表和 affiliation target。
3. 即使 target 没有独立文件，也能生成该 target。
4. 保留规则属性，使 `include:target @attr` 和 `@-attr` 仍可正确过滤。
5. 最后再去重，affiliation 本身不会输出到客户端规则。

新增 5 个测试，覆盖 include 属性过滤、已有 target、无独立文件的 target、affiliation 后再过滤以及 include 循环检测。

扫描的 V2Fly 快照：`6fe5416797ec88d29a3a1c69ce1431d73b955e88`。该快照整个 `data/` 当前没有非注释 affiliation 行，因此对本项目所有实际使用的 V2Fly source 造成的内容变化为 **0 条**。脚本缺陷已经修好；以后上游重新使用 `&target` 时不会再静默丢规则。

## 4. Egern AND 规则复核

原先漏掉的 SKK 规则是：

`AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,googlevideo.com))`

两个子条件都能由 Egern 表达：`protocol: udp` 与 `domain_suffix: googlevideo.com`。因此已在 `Ruleset/Egern/System/RejectNoDrop.yaml` 中转换为 1 条原生 `and_set`（使用 Egern 的 `!protocol` 与 `!domain_suffix` 类型标签），不再丢弃。`scripts/check.py` 只做了相应的安全解析兼容，不改变检查范围。

40 条 `PROCESS-NAME` 仍未转换，因为 Egern 规则集没有 process-name 类型；这与 AND 规则不是同一种限制。

## 5. “原自维护”来源回查

回查范围是重构后原先标记为 `SOURCE: custom` 的 69 个规则。检查顺序为 V2Fly 独立服务规则，再检查 blackmatrix7 独立规则；V2Fly 的大类聚合和公司级列表不冒充独立服务规则。blackmatrix7 检查快照为 `aa137cf64cda1474352875cc7e01b6f7d087cc0d`。

| 规则 | V2Fly | blackmatrix7 | 最终来源 |
| --- | --- | --- | --- |
| 1Password | 找到：agilebits | 未找到独立规则 | V2Fly |
| MastercardCN | 找到：mastercard 的 `@cn` 子集 | 未找到独立规则 | V2Fly |
| ByteDanceAI | 找到：doubao、bytedance-ai-!cn | 未找到独立规则 | V2Fly + 原自维护补充 |
| Grok | 找到：xai | 未找到独立规则 | V2Fly + 原自维护补充 |
| Gate | 找到：gateio | 未找到独立规则 | V2Fly + 原自维护补充 |
| HTX | 找到：huobi | 未找到独立规则 | V2Fly |
| Raindrop | 未找到 | 未找到 | 原自维护 |
| AntAfu | 未找到 | 未找到 | 原自维护 |
| MiniMax | 未找到 | 未找到 | 原自维护 |
| Qwen | 未找到 | 未找到 | 原自维护 |
| Zhipu | 未找到 | 未找到 | 原自维护 |
| HermesAgent | 未找到 | 未找到 | 原自维护 |
| Hanime1 | 未找到 | 未找到 | 原自维护 |
| AliExpress | 未找到 | 未找到 | 原自维护 |
| Allegro | 未找到 | 未找到 | 原自维护 |
| ASOS | 未找到 | 未找到 | 原自维护 |
| Etsy | 未找到 | 未找到 | 原自维护 |
| Flipkart | 未找到 | 未找到 | 原自维护 |
| iHerb | 未找到 | 未找到 | 原自维护 |
| Lazada | 未找到 | 未找到 | 原自维护 |
| MercadoLibre | 未找到 | 未找到 | 原自维护 |
| Mercari | 未找到 | 未找到 | 原自维护 |
| Noon | 未找到 | 未找到 | 原自维护 |
| SHEIN | 未找到 | 未找到 | 原自维护 |
| Temu | 未找到 | 未找到 | 原自维护 |
| Wayfair | 未找到 | 未找到 | 原自维护 |
| Zalando | 未找到 | 未找到 | 原自维护 |
| Aptos | 未找到 | 未找到 | 原自维护 |
| AptosExplorer | 未找到 | 未找到 | 原自维护 |
| Avalanche | 未找到 | 未找到 | 原自维护 |
| Bitcoin | 未找到 | 未找到 | 原自维护 |
| BitcoinCash | 未找到 | 未找到 | 原自维护 |
| Bitget | 未找到 | 未找到 | 原自维护 |
| Blockchair | 未找到 | 未找到 | 原自维护 |
| Blockscout | 未找到 | 未找到 | 原自维护 |
| BNBChain | 未找到 | 未找到 | 原自维护 |
| Cardano | 未找到 | 未找到 | 原自维护 |
| Chainlink | 未找到 | 未找到 | 原自维护 |
| Coinbase | 未找到 | 未找到 | 原自维护 |
| CryptoCom | 未找到 | 未找到 | 原自维护 |
| Dogecoin | 未找到 | 未找到 | 原自维护 |
| EtherFi | 未找到 | 未找到 | 原自维护 |
| Etherscan | 未找到 | 未找到 | 原自维护 |
| Hyperliquid | 未找到 | 未找到 | 原自维护 |
| Krak | 未找到 | 未找到 | 原自维护 |
| Mempool | 未找到 | 未找到 | 原自维护 |
| MEXC | 未找到 | 未找到 | 原自维护 |
| Monero | 未找到 | 未找到 | 原自维护 |
| NEAR | 未找到 | 未找到 | 原自维护 |
| PokePay | 未找到 | 未找到 | 原自维护 |
| Polkadot | 未找到 | 未找到 | 原自维护 |
| Polygon | 未找到 | 未找到 | 原自维护 |
| SAVO | 未找到 | 未找到 | 原自维护 |
| Solana | 未找到 | 未找到 | 原自维护 |
| Solscan | 未找到 | 未找到 | 原自维护 |
| Starryblu | 未找到 | 未找到 | 原自维护 |
| Stellar | 未找到 | 未找到 | 原自维护 |
| Sui | 未找到 | 未找到 | 原自维护 |
| SuiScan | 未找到 | 未找到 | 原自维护 |
| Tether | 未找到 | 未找到 | 原自维护 |
| TON | 未找到 | 未找到 | 原自维护 |
| TONViewer | 未找到 | 未找到 | 原自维护 |
| TRON | 未找到 | 未找到 | 原自维护 |
| TRONSCAN | 未找到 | 未找到 | 原自维护 |
| Uniswap | 未找到 | 未找到 | 原自维护 |
| USDC | 未找到 | 未找到 | 原自维护 |
| XRPL | 未找到 | 未找到 | 原自维护 |
| XRPScan | 未找到 | 未找到 | 原自维护 |
| Zcash | 未找到 | 未找到 | 原自维护 |

回查结果：6 个规则找到了更准确的 V2Fly 独立来源并更新来源标记；其中 3 个由 V2Fly 完整接管，3 个保留原自维护补充。其余 63 个在两个上游都没有独立服务规则，内容保持不变。

## 6. 第三方来源说明

新增 `THIRD_PARTY_NOTICES.md`，记录：

- v2fly/domain-list-community：MIT License
- blackmatrix7/ios_rule_script：GPL-2.0
- SukkaW/Surge（ruleset.skk.moe）：AGPL-3.0

只增加简单说明和链接，没有引入许可证管理系统。

## 7. 本轮结果摘要

- PaymentCN：补回 4 个旧支付域名。
- Shopping：检查 26 个，收窄 5 个公司级列表，21 个保持不变。
- affiliation：转换器已支持，新增 5 个测试；当前上游快照引起 0 条现有规则变化。
- Egern：补回 1 条可表达的 SKK AND 规则；40 条 PROCESS-NAME 继续明确排除。
- 原自维护回查：69 个全部完成；V2Fly 找到 6 个，blackmatrix7 独立规则找到 0 个，继续自维护 63 个。
- 客户端配置：0 个文件改动。
- 验证：6 个单元测试通过；402 个规则文件和 4 份客户端配置通过 YAML、重复项与本仓库 URL 检查；12 组本轮修改的 Mihomo/Egern 域名规则逐项一致。
