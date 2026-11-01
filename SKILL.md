---
name: vpn-skill
description: "本地代理池管理：启动混合节点池代理并让命令走代理、用完自动关闭。触发样例：'开代理'、'关代理'、'代理'、'翻墙'、'访问 GitHub/Google 慢或失败'、'节点测速'、'代理状态'"
---

# vpn-skill 使用指引

本地自包含代理工具：拉起 mihomo 内核组成「机场订阅 + 免费源」平权混池，命令粒度走代理，空闲自动熔断关闭。全部操作经唯一 CLI 入口完成。

**调用形态**（路径以本文件所在目录为准，`<本skill绝对路径>` 即本 SKILL.md 所在目录）：

```
node <本skill绝对路径>/scripts/vpn.js <子命令>
```

子命令：`bootstrap`（首次装内核）`setup`（配订阅）`start` `stop` `restart` `status` `update` `test` `doctor` `export`（延迟 Top N 节点导出）。所有命令输出英文行 + `===JSON===` 尾块（单行 JSON，以此为准解析）；退出码 0=成功 / 1=失败 / 2=成功带警告。

## 一、何时启用

任务需要访问境外资源（GitHub/Google/npm registry 等）且出现**超时、失败或明显变慢**时才启用。不要预启动、不要在任务无需代理时"顺手开着"。任务完成后必须 `stop`（空闲保险丝也会自动关，但主动关更干净）。

## 二、标准流程（四步）

1. **start**：`node <本skill绝对路径>/scripts/vpn.js start`。首启含免费源拉取，需数十秒。
2. **读 proxy_port**：从 start（或 `status`）的 JSON 输出取 `proxy_port`（默认 7891）。
3. **每条需代理的命令加前缀**（端口以实际输出为准）：

   ```
   HTTP_PROXY=http://127.0.0.1:7891 HTTPS_PROXY=http://127.0.0.1:7891 ALL_PROXY=http://127.0.0.1:7891 NODE_USE_ENV_PROXY=1 <命令>
   ```

   **注意：export 无效**——Bash 每次调用是独立 shell，环境变量不跨命令保留，因此**每条**需要走代理的命令都要带前缀，不能 export 一次了事。`NODE_USE_ENV_PROXY=1` 让 node 自身 fetch 也走该代理（本机 node v25.2.1 实测有效）；Git Bash 下 curl/git/npm 认 `HTTPS_PROXY/ALL_PROXY`。
4. **用完 stop**：`node <本skill绝对路径>/scripts/vpn.js stop`。

**稳健指引**：start 成功后先 `status` 确认 `current_node` 非空且**不是 COMPATIBLE** 再发业务请求——url-test 首轮要对全池（数千节点）测速，启动后最初一段时间可能较慢或 `pool_alive` 偏低，属正常收敛过程；若 1-2 分钟后 `current_node` 仍为 COMPATIBLE 或 `pool_alive` 为 0，按第四节异常处理走。

## 三、状态字段含义（status 的 JSON）

| 字段 | 含义 |
| --- | --- |
| `current_node` | 当前选优节点（url-test 自动切换；COMPATIBLE=尚未完成首轮选优） |
| `pool_total` / `pool_alive` | 池总节点数 / 存活节点数（订阅+免费源混池） |
| `idle_s` | 距最近一次有效流量的秒数（保险丝判定依据） |
| `speed_up_bps` / `speed_down_bps` | 最近采样的上/下行速率（字节/秒） |
| `watcher_dead` | 守护进程心跳是否超时（true=异常，下次任意命令会自动收殓） |
| `degraded` | 池全挂标记（true 时代理请求会失败，需走异常处理） |

## 四、异常处理（分流，不无限重试）

请求失败时先 `doctor` 看诊断（`checks` 数组逐项 ok/fail），按 fail 项分流：

- **`pool` 项 POOL:EMPTY / `degraded`** → `update` 强制重拉全部源 → 重试一次业务请求 → 仍失败则告知用户「免费源当前不可用，建议检查机场订阅」。
- **`kernel` 项缺失**（首次使用或内核损坏）→ `bootstrap` 重装内核（注意：已装旧版时需先删除 `kernel.json` 才会触发重新下载；内核运行中直接重跑 bootstrap 会自动停止、替换并在升级后自动恢复运行）。doctor 的 `[warn] kernel update available` 行表示官方有新版。
- **端口漂移**（start 输出的端口与上次不同）→ 用新端口重拼前缀即可，不是故障。
- **`sub-providers` 项 FETCH FAILED**（订阅拉取失败）→ **告知用户检查/更新订阅 URL**（这是用户侧动作，agent 无法自修）。更新订阅时优先建议用户在自己的终端交互式运行 `setup`（按提示输入 URL，URL 不经 Claude 命令行与对话）；若由 Claude 以 `setup --sub <URL>` 代跑，须向用户明示「该 URL 已进入当次对话记录」（后续日志/输出/git 零出现，对话记录本身不在 skill 控制面——设计 §6 边界）。配置完成后 `restart` 生效。
- **重试纪律**：每条分支最多重试一次，仍失败即如实向用户报告诊断结论，不无限循环。

## 五、行为护栏（红线，任何情况下不得违反）

1. **绝不修改系统代理/DNS 设置**：本 skill 只监听本机回环端口，靠命令前缀走代理；不碰注册表、不碰 Internet Settings、不开 TUN。
2. **绝不杀 FlClash 进程**：用户可能同时运行 FlClash（占用 7890/9090，本 skill 已硬编码永不使用这两个端口）；只管理本 skill 自己拉起的进程。
3. **订阅 URL 不写入任何报告/日志/对话输出**：订阅 URL 含凭据，只存在于 `user/subscriptions.yaml` 与 `var/config.yaml`（均被 gitignore）；诊断输出只有截断 host 形态。
4. **敏感明文凭据不走代理**：涉及密码/token 等敏感明文凭据的操作（登录、认证、带密钥的请求）直连执行、不加代理前缀——免费节点存在流量可见性风险（出口方可见连接元数据）。
5. **导出文件即凭据集合**：`exports/top100.yaml` 为导出的免费节点凭据集合（仅免费节点、订阅节点四重防御不可达，含服务器地址/密码）。该文件**随仓库分发**（免费节点源自公开聚合源，可公开）；但若使用者手动向其中混入订阅节点，则该文件立即不得再提交/分享。
