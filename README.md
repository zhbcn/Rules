# zhbcn/Rules

这是我自己使用的分流规则库。客户端只读取本仓库里的成品规则，不在运行时依赖上游项目。

## 规则从哪里来

整理某个服务时，按下面的顺序查找：

1. 优先使用 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。
2. V2Fly 没有时，再使用 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)。
3. 两边都没有时，保留并审核本仓库已有的自维护规则。
4. 仍然缺少时，根据服务官方域名和实际使用情况补充。

每个规则文件顶部都写明来源和上游列表。即使上游以后改名、移动或删除，本仓库里的完整副本仍可继续使用。

## 两种客户端格式

- `Ruleset/Mihomo/`：供 Clash Party 和 FlClash 使用，采用 `payload` classical YAML。
- `Ruleset/Egern/`：供 Egern 使用，采用 Egern 原生的 `domain_suffix_set`、`domain_set`、`ip_cidr_set` 等集合。

不再单独维护 Surge 目录。Clash Party 与 FlClash 共用 Mihomo 文件，Egern 使用自己的原生文件。

## Finance、Crypto 和 PaymentCN

- `PaymentCN`：支付宝、微信支付、银联、京东支付、抖音支付及中国区银行卡组织域名，默认直连。
- `Finance`：Wise、PayPal、银行、券商、银行卡组织和 TradingView 等传统金融服务。
- `Crypto`：交易所、钱包、公链、DeFi、区块浏览器和加密货币行情服务。

仓库仍保留 Binance、Bybit、OKX、Wise 等独立规则，方便以后单独分流；客户端默认只加载三个聚合文件，避免同时维护几十条引用。

## 更新规则

更新 V2Fly 规则时使用：

```powershell
python scripts/convert_v2fly.py `
  --data D:\path\to\domain-list-community\data `
  --list wise `
  --name Wise `
  --mihomo Ruleset\Mihomo\Finance\Wise.yaml `
  --egern Ruleset\Egern\Finance\Wise.yaml
```

转换器会递归展开 `include`、处理 include 属性筛选、检测循环引用并删除完全重复的规则。V2Fly 的普通域名、`full:`、`keyword:` 和 `regexp:` 会分别转换为两个客户端支持的对应类型。

完成修改后运行：

```powershell
python scripts/check.py `
  --config "D:\dev\配置文件\Clash Party.yaml" `
  --config "D:\dev\配置文件\Ash（FlClash）.yaml" `
  --config "D:\dev\配置文件\吹雪（FlClash）.yaml" `
  --config "D:\dev\配置文件\Egern.yaml"
```

检查脚本会验证规则 YAML、完全重复项，以及配置中引用的 zhbcn/Rules 文件是否真实存在。
