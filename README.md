# Shadowrocket Policy

合并公开上游规则，生成带 `pre-matching` 的原生拒绝模块和国内直连规则。每日 10:23 UTC 自动更新。

## 使用

在 Shadowrocket「配置 → 模块 → +」导入隐私模块：

```text
https://raw.githubusercontent.com/cresseelia/shadowrocket-policy/main/generated/native-reject.module
```

模块名称为 `Shadowrocket Privacy Reject`，独立于 iOS-NOIR。保留上述 GitHub 订阅地址，使用「更新模块」获取新版本；开启模块页「保存到 iCloud」可同步模块。GitHub 提供规则更新，iCloud 同步模块数据，两者分别负责不同用途。

主配置关闭 HTTPS/SVCB DNS 查询转发，并引用国内规则集（合并到已有段落）：

```ini
[General]
allow-dns-svcb = false

[Rule]
RULE-SET,https://raw.githubusercontent.com/cresseelia/shadowrocket-policy/main/generated/direct.list,DIRECT
```

主配置继续保留自己的节点、自建 DNS、特殊分流和最终策略。正式隐私模块只包含拒绝规则，不修改全局 DNS 设置。全量模块已在手机加载，DNS 抽样对照通过；具体 App 功能仍需逐项验证。启用后停用被替代的 GMO reject/direct 模块和重复拒绝引用，GMO 数据仍作为上游每日合并。

证书、Plugin2Rocket、HTTPDNS、广告平台、墨鱼及实际需要的小红书/彩云/DiDiClean 功能模块继续按需使用。

## 维护

Python 3.11+，不需要额外依赖：

```sh
python3 -m unittest -v
python3 generate.py
```

`sources.toml` 管理上游和覆盖检查；`corrections.toml` 登记经确认的例外。例外只退出提前拒绝，已有连接规则仍需相应修正。`reject-deferred.list` 非空时，在具体正常路由之后引用并指定 REJECT。`manifest.json` 记录来源哈希、更新状态和数量。

下载或校验失败不发布新结果。部分上游不可用时使用有期限的快照，过期停止更新。规则来源包括 blackmatrix7、GMOogway、Vincent-Loeng/Loyalsoldier 和可莉插件中心，各上游许可与署名要求继续适用。

仅公开规则与生成工具，私有配置放在已忽略的 `private/`。
