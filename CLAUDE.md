# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 仓库性质

自包含的 Claude Code skill（代理池管理）：Node.js CLI + 内置 mihomo 内核子进程。**拷贝单位=本目录整体**——运行时禁止引用本目录之外的任何资源（`bin/mihomo.exe` 首次由 `bootstrap` 从官方 release 三级引导链下载，不入库）。无 npm 依赖（yaml 包已拷入 `scripts/vendor/`）——**禁止引入运行时 install**。

## 常用命令

```powershell
node scripts/vpn.js <bootstrap|setup|start|stop|restart|status|update|test|doctor|export>
# 语法快查（无测试框架，改动后至少跑）：
node --check scripts/vpn.js; node --check scripts/lib/<改动文件>.js
# 真机验证循环（改动后的标准回归）：
node scripts/vpn.js start; node scripts/vpn.js status; node scripts/vpn.js test; node scripts/vpn.js stop
# 零残留检查（stop 后）：
Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -ge 7891 -and $_.LocalPort -le 9100}
```

注意：start 后 url-test 需 1-2 分钟完成首轮大池测速，期间 `test` 可能失败属正常——验证前等待或看 `status` 的 `pool_alive`。保险丝参数可热调（`runtime.json` 的 `idle_window_s`，无需重启）。

## 三条红线（改代码的硬约束，违反即事故）

- **R1 系统网络设置零触碰**：config 模板静态禁键（tun/tproxy-port/redir-port/dns/external-controller-pipe/external-doh-server——config.js 有运行时断言）；零注册表/netsh/防火墙/DNS 写调用
- **R2 订阅凭据零外泄**：订阅 URL 只存 `user/subscriptions.yaml` 与生成的 `var/config.yaml`（均 gitignore）；一切日志经脱敏管道（见下）；**git 提交前确认无 subscriptions/var/内容混入**（本仓库公开分发）
- **R3 不干扰 FlClash**：端口候选硬编码排除 {7890,9090}（util.js）；kill 仅 PID+exe 路径双校验（core.js），**绝不按进程名杀**

## 架构大图（跨文件才能理解的部分）

**进程拓扑与生命周期**：`vpn.js`(CLI，短期) --detached+unref--> `watcher.js`(常驻守护) --spawn(detached:false, stdio:pipe)--> mihomo 内核。互守：内核死→watcher 写终态自退；watcher 死→心跳收殓兜底（`core.js` 的收殓逻辑同时覆盖孤儿/陪葬两形态——本环境实测 pipe 子进程随父陪葬，见 `.claude` 知识库 agent-shell-child-process-lifecycle 条目，勿信 POSIX「父退子孤」惯例）。

**runtime.json 多写者协议**：CLI 与 watcher 并发写共享状态文件，**所有写入必须走 `util.writeRuntimeAtomic`**（读快照→仅改本写者字段→write_seq 条件原子写→冲突重试≤3）——直接全量覆盖会丢其他写者的字段（心跳/last_channel 等）。

**日志脱敏链（R2 核心）**：mihomo stdio → watcher 管道消费 → `util.sanitize`（两层：`buildKnownSecrets` 三粒度已知凭据替换——完整 URL/去 query 前缀/host + 模式正则兜底）→ `var/logs/mihomo.log`。watcher 自身日志为白名单制（仅事件与统计量）。改日志相关代码时必须保持内核无文件直写路径。

**节点池双轨**：订阅=http provider **直连**拉取（R2 要求：凭据不得经池内节点外发，即使 mihomo 支持 proxy 字段也不可用）；免费源=Node 层 `providers.js` 多通道拉取（direct/jsdelivr/ghproxy 降级+last_channel 优选）→ file provider 缓存。两类平权汇入单 url-test 组 `include-all`（`unified-delay` 必开）。`uri-parser.js` 处理 vmess/vless/trojan/ss 分享链接源（sources.yaml 的 `format: uri`）。

**Top 导出**：`export-top.js` 从 `/providers/proxies` 端点取延迟 history（注意：`/proxies` 端点不含 provider 节点数据），仅免费节点（四重防御排除订阅），写 `exports/top100.yaml`——该文件**随仓库分发**（免费节点源自公开聚合源）。

**输出契约**：所有命令=英文 ASCII 行 + `===JSON===` 尾块单行 JSON；退出码 0/1/2。`cmd-*.js` 为自输出形态（handler 返回退出码数字），`core.js` 的 cmd* 为框架形态（返回对象）——vpn.js 主入口对两种形态都兼容。

## 环境事实（Windows 特有）

- node stdout 恒 UTF-8，GBK 控制台显示中文会乱码——人类可读输出一律 ASCII（`util.toAscii`），JSON 行保留 UTF-8（节点名）
- 本机路径含中文用户名（`C:\Users\张\...`）——进程路径校验（`core.js` pidPathOwned）前置了 PowerShell OutputEncoding=UTF8，勿删
- mihomo 日志中的订阅地址有三种形态（完整 URL / 去 query 前缀 / `host:port`）——knownSecrets 三粒度缺一不可
