# vpn-skill

本地自包含代理工具：一条命令拉起 mihomo 内核，把「机场订阅 + 三个免费节点源」混成一个平权节点池（自动测速选优），命令加环境变量前缀即走代理，空闲 10 分钟自动熔断关闭。零安装、零系统侵入——不注册系统代理、不改 DNS、不干扰你正在跑的 FlClash。

## 首次使用

```bash
# 1. 获取内核（官方 release 多镜像引导链，约 20MB）
node scripts/vpn.js bootstrap

# 2. 配置机场订阅（URL 只存本机 user/subscriptions.yaml，不进任何日志）
node scripts/vpn.js setup --sub <你的订阅URL>

# 3. 启动（首启含免费源拉取，稍慢；完成后输出代理端口与前缀模板）
node scripts/vpn.js start
```

日常用 `start` / `stop` 即可；状态看 `status`。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `node scripts/vpn.js start` | 启动代理池（已在跑则直接返回现状） |
| `node scripts/vpn.js stop` | 停止并清理全部进程（未运行也无副作用） |
| `node scripts/vpn.js restart` | 重启（换端口/换配置后用） |
| `node scripts/vpn.js status` | 查看状态：当前节点/池存活/速率/空闲秒数 |
| `node scripts/vpn.js test` | 经代理实测连通性（默认 gstatic 204） |
| `node scripts/vpn.js test --all` | 全池测速，输出最快 5 节点与当前节点延迟（固定约 1 分钟窗口） |
| `node scripts/vpn.js update` | 强制重拉全部节点源并热更新 |
| `node scripts/vpn.js doctor` | 逐项体检（内核/端口/进程/源/池/订阅/状态文件）并自动清理残留 |
| `node scripts/vpn.js export` | 按延迟导出 Top100 免费节点到 `exports/top100.yaml`（随仓库分发） |

所有命令输出英文说明行 + `===JSON===` 尾块（单行 JSON 可脚本解析）；退出码 0=成功 / 1=失败 / 2=成功带警告。

## 让命令走代理

`start`/`status` 输出里有拼好的前缀模板（端口以实际输出为准，默认 7891）：

```bash
HTTP_PROXY=http://127.0.0.1:7891 HTTPS_PROXY=http://127.0.0.1:7891 ALL_PROXY=http://127.0.0.1:7891 NODE_USE_ENV_PROXY=1 curl https://www.gstatic.com/generate_204
```

注意 export 不跨命令保留，每条要走代理的命令都得带前缀。

## Top100 导出

每次节点更新并测速后（`update` 成功、或后台每小时定时刷新成功），自动把**延迟最低的前 100 个免费节点**导出到 `exports/top100.yaml`（clash proxies 格式，固定名覆盖；仅免费节点——订阅节点四重防御不可达，你自己的客户端里已有）。**该文件随仓库分发**：clone 仓库的用户可直接把它导入 FlClash 等 Clash 系客户端获得一份精选免费节点；运行 `export` 会刷新它，随仓库提交即可保持精选新鲜。也可手动触发：

```bash
node scripts/vpn.js export          # 默认前 100
node scripts/vpn.js export --top 5  # 自定义数量
```

把该文件拷贝到 FlClash 等客户端导入即可。**注意：文件内是完整节点凭据（服务器地址/密码），仅供本机导入使用，勿分享/上传**；延迟数据来自运行中的内核，内核未启动时 export 会提示先 `start`。

## 三条红线承诺

1. **不动系统网络设置**：不注册系统代理、不改 DNS、不开 TUN/网卡，只监听本机回环端口。
2. **不干扰 FlClash**：永不占用 7890/9090，只终止自己拉起的进程（PID+路径双校验）。
3. **订阅凭据不外泄**：订阅 URL 只存于本机两个 gitignore 文件；一切日志/输出经两层脱敏，失败信息只有截断 host。

## 端口与文件布局

- 端口：代理 7891-7900、控制 9091-9100 两段内自动挑空闲（硬编码排除 FlClash 的 7890/9090）；实际端口见 start/status 输出。
- `bin/` 内核（mihomo.exe，旧版留 .prev 可回滚）；`user/` 你的订阅与免费源清单（sources.yaml 可自行增删源）；`var/` 运行时状态与日志（可随时删，自动重建）；`scripts/` 本体。
- 内核升级：删除 `kernel.json` 后重跑 `bootstrap`（doctor 会比对官方 latest 并提示新版；内核运行中重跑会自动停止、替换并自动恢复运行）。免费源：修改通道跑 `update` 即生效；**新增/删除源需 `restart` 生效**（`update` 会重新生成 config 并对新增源给出提示）。

## 故障排查

任何异常先跑 `node scripts/vpn.js doctor`：逐项报告内核/端口/进程/免费源可达性/池健康/订阅拉取/状态文件，并自动清理自家残留进程（清完再跑一遍应全绿）。`checks` 数组里带 `ok:false` 的项即问题所在，`detail` 有对应处理建议。
