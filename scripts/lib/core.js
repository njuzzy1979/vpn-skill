// core.js — mihomo 内核生命周期 + start/stop/status 完整链路（§2/§3.4/§8）：
//   t3 形态——cmdStart=首拉免费源→config.generate→detached spawn watcher→CLI 等就绪信号；
//   mihomo 由 watcher 以 detached:false 接管互守（spawnCore 注入点）；kill 全部 PID+路径
//   （或 PID+身份）双校验；惰性收殓（孤儿扫描+心跳维度）；start 失败清理序列（§2②）
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const util = require('./util');
const providers = require('./providers');
const config = require('./config');

// ---------- mihomo external-controller 本机客户端（127.0.0.1，Bearer 认证） ----------

// 所有失败一律 resolve(null)：本 API 在 t1 仅用于探针/尽力取值，容错优先
function apiRequest(apiPort, secret, method, apiPath, timeoutMs) {
  return new Promise(resolve => {
    const req = http.request({
      host: '127.0.0.1', port: apiPort, path: apiPath, method,
      timeout: timeoutMs || 3000,
      headers: { Authorization: 'Bearer ' + secret },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// 无认证探测：任何 HTTP 应答（含 401）都证明候选段端口上有 listener——孤儿扫描用
function apiProbeAnyAnswer(apiPort, timeoutMs) {
  return new Promise(resolve => {
    const req = http.request({ host: '127.0.0.1', port: apiPort, path: '/version', method: 'GET', timeout: timeoutMs || 800 }, res => {
      res.resume();
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
}

// 就绪探针（§2⑤）：轮询 /version 至应答且带版本字段，总超时 timeoutMs
async function waitVersion(apiPort, secret, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await apiRequest(apiPort, secret, 'GET', '/version', 1500);
    if (r && r.status === 200) {
      try {
        const j = JSON.parse(r.body);
        if (j && typeof j.version === 'string') return j.version;
      } catch (e) { /* body 非完整 JSON：继续轮询 */ }
    }
    await sleep(400);
  }
  return null;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---------- 进程校验与终止（R3 铁律：绝不按进程名杀；仅 PID+路径双校验通过才 kill） ----------

function pidAlive(pid) {
  if (!pid || typeof pid !== 'number') return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code === 'EPERM'; } // Windows：存在但无权限信号=活；ESRCH=已死
}

// 经 PowerShell Get-Process 取进程 exe 路径（只读查询，§8；前置 OutputEncoding=UTF8 防中文路径 GBK 乱码）
function exePathOfPid(pid) {
  const cmd = '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ' +
    '(Get-Process -Id ' + pid + ' -ErrorAction SilentlyContinue).Path';
  return new Promise(resolve => {
    const p = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
      { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    let out = '';
    p.stdout.setEncoding('utf8');
    p.stdout.on('data', c => { out += c; });
    p.on('error', () => resolve(null));
    p.on('close', () => resolve(out.trim() || null));
    setTimeout(() => { try { p.kill(); } catch (e) { /* 已退出 */ } resolve(out.trim() || null); }, 5000);
  });
}

// 双校验核心：exe 路径必须位于本 skill bin/ 内（防 PID 复用误杀 FlClashCore 等，R3）
async function pidPathOwned(pid, root) {
  const exePath = await exePathOfPid(pid);
  if (!exePath) return false;
  const binDir = path.join(root, 'bin').toLowerCase();
  const rel = path.relative(binDir, exePath.toLowerCase());
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

// 优雅停序列（§3.4）：DELETE /connections 清连接（尽力）→ taskkill /PID /T /F → 等待退出确认
// 调用前提：调用方已完成 PID+路径双校验
async function killMihomo(pid, apiPort, secret) {
  if (apiPort && secret) await apiRequest(apiPort, secret, 'DELETE', '/connections', 2000);
  await new Promise(resolve => {
    const tk = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    tk.on('error', () => resolve());
    tk.on('close', () => resolve());
  });
  for (let i = 0; i < 25 && pidAlive(pid); i++) await sleep(200); // 退出确认 ≤5s
  return !pidAlive(pid);
}

// ---------- watcher 进程校验与终止（R3：watcher=node 进程，防误杀其他 node） ----------
// 取舍（任务书⑥）：watcher 的 exe=process.execPath（系统级 node.exe），无法像 mihomo 那样
// 校验「路径在 skill bin/ 内」。可得的最强校验=CIM 查询一次拿双因子：
//   ① CommandLine 含本 skill scripts\lib\watcher.js 绝对路径（进程专用，其他 node 进程不含）
//   ② CreationDate 与 runtime.watcher_start_ts（spawn 后采集）一致（±3s，防 PID 复用）
// 任一因子不可得/不匹配 → 拒杀（fail-safe：mihomo 已停时 watcher 本就会因互守自退，
// 拒杀只会留一个即将自退的进程，不会误杀无关 node）

// CIM 查询 watcher 身份：{ok:CommandLine 校验, creationTs:Unix 秒} 或 null（查询失败）
function watcherIdentity(pid, root) {
  if (!pid || typeof pid !== 'number') return Promise.resolve(null);
  const watcherJs = path.join(root, 'scripts', 'lib', 'watcher.js');
  const cmd = '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ' +
    '$p = Get-CimInstance Win32_Process -Filter "ProcessId=' + pid + '"; ' +
    'if ($p) { [Console]::WriteLine(($p.CommandLine -replace "`r|`n", " ")); ' +
    '[Console]::WriteLine([DateTimeOffset]::new($p.CreationDate).ToUnixTimeSeconds()) }';
  return new Promise(resolve => {
    const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd],
      { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    let out = '';
    ps.stdout.setEncoding('utf8');
    ps.stdout.on('data', c => { out += c; });
    ps.on('error', () => resolve(null));
    ps.on('close', () => {
      const rows = out.trim().split(/\r?\n/);
      if (rows.length < 2 || !rows[0]) return resolve(null);
      const cl = rows[0].toLowerCase();
      const ts = Number(rows[1]);
      resolve({
        ok: cl.includes(watcherJs.toLowerCase()),
        creationTs: Number.isFinite(ts) ? ts : null,
      });
    });
    setTimeout(() => { try { ps.kill(); } catch (e) { /* 已退出 */ } resolve(null); }, 5000);
  });
}

// kill watcher：身份校验通过才 taskkill（R3：绝不按进程名；PID+身份双因子）
async function killWatcher(rt, root, lines) {
  const pid = rt.watcher_pid;
  if (!pid || !pidAlive(pid)) return false;
  const ident = await watcherIdentity(pid, root);
  if (!ident || !ident.ok) {
    lines.push('Warning: watcher pid ' + pid + ' identity unverified -- not killed (will self-exit via mutual guard)');
    return false;
  }
  if (ident.creationTs !== null && rt.watcher_start_ts &&
      Math.abs(ident.creationTs - rt.watcher_start_ts) > 3) {
    lines.push('Warning: watcher pid ' + pid + ' creation-time mismatch -- not killed (PID reuse suspected)');
    return false;
  }
  await new Promise(resolve => {
    const tk = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    tk.on('error', () => resolve());
    tk.on('close', () => resolve());
  });
  for (let i = 0; i < 15 && pidAlive(pid); i++) await sleep(200);
  return !pidAlive(pid);
}

// ---------- 孤儿扫描与收殓（§3.4 惰性清理兜底 + §4.1 损坏恢复的 t1 形态） ----------
// 设计完整规则：mihomo 存活（PID 存在 + /version 应答 + exe 在本 skill bin/ 内）但心跳超 120s → 收殓。
// t1 无 watcher（心跳停滞是常态），故收殓判定不依赖心跳，改为「候选端口段探活 + netstat 定位 PID + 路径双校验」：
//   - 路径校验通过的自家残留 → kill（含 runtime.json 损坏/失真场景的全量探活重建语义）
//   - 路径校验不通过（端口被外部进程占用）→ 绝不杀，仅告警
// 心跳维度的收殓（收编重启 watcher）待 t3 watcher 落地后接入

// netstat -ano -p tcp 解析 LISTENING 行 → Map<port, pid>
function netstatListenPids() {
  return new Promise(resolve => {
    const p = spawn('netstat', ['-ano', '-p', 'tcp'], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    let out = '';
    p.stdout.setEncoding('utf8');
    p.stdout.on('data', c => { out += c; });
    p.on('error', () => resolve(new Map()));
    p.on('close', () => {
      const m = new Map();
      for (const ln of out.split(/\r?\n/)) {
        const mm = ln.trim().match(/^TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)$/);
        if (mm) { const port = Number(mm[2]); if (!m.has(port)) m.set(port, Number(mm[3])); }
      }
      resolve(m);
    });
  });
}

// 扫描候选两段端口（proxy 7891-7900 / api 9091-9100，硬编码排除 7890/9090——R3），
// 对有 listener 且属自家 bin/ 的残留执行清理；返回清理记录
async function reapOrphans(root, lines) {
  const ports = [...util.PROXY_PORT_CANDIDATES, ...util.API_PORT_CANDIDATES];
  const answers = await Promise.all(ports.map(p => apiProbeAnyAnswer(p, 600)));
  const livePorts = ports.filter((p, i) => answers[i]);
  if (livePorts.length === 0) return [];
  const pidMap = await netstatListenPids();
  const reaped = [];
  for (const port of livePorts) {
    const pid = pidMap.get(port);
    if (!pid) { lines.push('Warning: port ' + port + ' answers but no LISTENING pid found -- skipped'); continue; }
    if (!(await pidPathOwned(pid, root))) {
      lines.push('Warning: port ' + port + ' held by pid ' + pid + ' outside skill bin/ -- not killed (safety)');
      continue;
    }
    await killMihomo(pid, null, null);
    lines.push('Reaped orphan kernel: port ' + port + ' pid ' + pid);
    reaped.push({ port, pid });
  }
  return reaped;
}

// ---------- mihomo spawn 与日志管道（§8：stdio pipe → 脱敏 → var/logs/mihomo.log） ----------

// 行缓冲消费者：流按行拆分交 handler。t1 handler=脱敏落盘；t3 watcher 以自身 handler 替换（移交点）
function attachLineConsumer(stream, onLine) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', chunk => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, '');
      buf = buf.slice(idx + 1);
      try { onLine(line); } catch (e) { /* 消费异常不反噬 */ }
    }
  });
  stream.on('end', () => { if (buf) { try { onLine(buf); } catch (e) { /* 同上 */ } } });
}

// spawn mihomo：-d var（HomeDir=var/，provider path 相对它，SAFE_PATHS 合规）-f var/config.yaml
// opts.configPath / opts.knownSecrets / opts.onLogLine / opts.detached 均为可注入点（测试与 watcher 移交用）。
// detached 默认 true：t1 由 CLI 直启（短命进程），detached 使内核在 CLI 退出后存活（实测：本环境
// 命令子进程随父退出被 job 收割，非 detached 的内核活不过 CLI）；t3 watcher 接管时传 detached:false
// 恢复 §8 的父子互守形态（watcher 常驻持管道）。CLI 存活期间照常消费管道并脱敏落盘；CLI 退出后
// 管道关闭、内核后续日志丢失（t1 已知局限，由 t3 watcher 关闭）
function spawnCore(root, opts) {
  const o = opts || {};
  const P = util.paths();
  const configPath = o.configPath || P.varConfig;
  const logFile = o.logFile || P.mihomoLog;
  const knownSecrets = o.knownSecrets || [];
  const onLine = o.onLogLine || (line => util.appendLogLine(logFile, util.sanitize(line, knownSecrets)));
  const detached = o.detached !== undefined ? o.detached : true;
  const child = spawn(P.kernelExe, ['-d', P.varDir, '-f', configPath], {
    detached,
    stdio: ['ignore', 'pipe', 'pipe'], // §8：stdin 关闭，stdout/stderr 管道由本进程消费
    windowsHide: true,
  });
  if (detached) child.unref(); // CLI 不等内核退出；生命周期由 runtime.json+stop 管理
  attachLineConsumer(child.stdout, onLine);
  attachLineConsumer(child.stderr, onLine);
  // 子进程退出仅记录（t1 由调用方处置；t3 watcher 接管 exit 事件写终态）
  child.on('exit', (code, signal) => {
    try { onLine('[core] mihomo exited code=' + code + ' signal=' + signal); } catch (e) { /* 忽略 */ }
  });
  return { child, pid: child.pid, onLine };
}

// ---------- t1 最小配置（内联；完整 config 生成归 t2 lib/config.js） ----------

// 静态审计基准（§4.1/§7 R1）：本模板不含 tun/tproxy-port/redir-port/dns/pipe/doh 键
function buildMinimalConfig(opts) {
  return [
    'mixed-port: ' + opts.proxyPort,
    'allow-lan: false',
    'mode: rule',
    'unified-delay: true',
    'log-level: info',
    'external-controller: 127.0.0.1:' + opts.apiPort,
    'secret: ' + opts.secret,
    'proxy-providers:',
    '  fixture:',
    '    type: file',
    '    path: providers/fixture.yaml',
    "    health-check: {enable: true, url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 5000, expected-status: 204}",
    'proxy-groups:',
    '  - name: POOL',
    '    type: url-test',
    '    include-all: true',
    "    url: 'https://www.gstatic.com/generate_204'",
    '    interval: 300',
    '    tolerance: 100',
    'rules:',
    '  - MATCH,POOL',
    '',
  ].join('\n');
}

// 测试 fixture：两个不可达假节点（占位池，验证生命周期用；t2 由 providers.js 免费源缓存取代）
// 假凭据为明文占位符，仅存在于 var/providers/ 数据文件（R2 管控对象是日志/外发，不含本文件）
function ensureFixture(root) {
  const P = util.paths();
  fs.mkdirSync(P.varProviders, { recursive: true });
  const f = path.join(P.varProviders, 'fixture.yaml');
  if (fs.existsSync(f)) return f;
  const fixture = [
    '# t1 test fixture: unreachable placeholder nodes (replaced by real sources in t2)',
    'proxies:',
    '  - name: fixture-ss',
    '    type: ss',
    '    server: 127.0.0.1',
    '    port: 47613',
    '    cipher: aes-128-gcm',
    '    password: fixture-placeholder',
    '  - name: fixture-vmess',
    '    type: vmess',
    '    server: 127.0.0.1',
    '    port: 47614',
    '    uuid: 00000000-0000-0000-0000-000000000000',
    '    alterId: 0',
    '    cipher: auto',
    '',
  ].join('\n');
  fs.writeFileSync(f, fixture, 'utf8');
  return f;
}

// ---------- 运行态辅助 ----------

function ensureVarDirs() {
  const P = util.paths();
  fs.mkdirSync(P.varLogs, { recursive: true });
  fs.mkdirSync(P.varProviders, { recursive: true });
}

// GET /proxies 解析 POOL 组状态（current_node / pool_total / pool_alive）；尽力而为，失败 null
async function poolStats(apiPort, secret) {
  const r = await apiRequest(apiPort, secret, 'GET', '/proxies', 2500);
  if (!r || r.status !== 200) return null;
  let j;
  try { j = JSON.parse(r.body); } catch (e) { return null; }
  const proxies = j && j.proxies;
  if (!proxies || !proxies.POOL) return null;
  const g = proxies.POOL;
  const all = Array.isArray(g.all) ? g.all : [];
  let alive = 0;
  for (const name of all) { if (proxies[name] && proxies[name].alive) alive++; }
  return { current_node: g.now || null, pool_total: all.length, pool_alive: alive };
}

// ---------- 子命令：start（§2 数据流完整链路，t3） ----------
// ①providers.refreshAll 首拉（失败写空池占位不阻塞）→ ②试绑定→config.generate（实得端口
// 传参，t2 收口点）→ ③runtime 预写（watcher 由此读 api_port/secret）→ ④detached+unref
// spawn watcher（t1 实测：非 detached 子进程随父退出被收割）→ ⑤CLI 轮询就绪信号
// （watcher 探针过→写 state=running），15s 超时→失败清理序列（kill watcher+mihomo+终态）

// 心跳维度收殓（§3.4 惰性清理，t3 启用——t1 遗留③）：mihomo 活+/version 应答但心跳超
// 120s（watcher 死）→ 收殓（killMihomo+清状态）。cmdStart/cmdStatus 共用
async function reapByHeartbeat(root, rt, lines) {
  const hbAge = Math.floor(Date.now() / 1000) - (rt.heartbeat_ts || 0);
  await killMihomo(rt.mihomo_pid, rt.api_port, rt.secret);
  util.writeRuntimeAtomic(root, s => {
    s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'watcher-dead-reaped';
    // t3 遗留 1（t4 收口）：收殓路径写 reaper 标记——真 watcher 的 exit handler 读它
    // 把本次 mihomo 之死标为 reaped 而非 manual-stop（watcher.log 事件标签不再歧义）
    s.reaper = 'heartbeat-stale';
  });
  lines.push('Reaped orphan kernel (watcher heartbeat stale ' + hbAge + 's): pid ' + rt.mihomo_pid);
  return true;
}

// start 失败清理序列（§2② 扩展：双方进程都清，不留残留进程/端口）
async function cleanupStartFailure(root, lines, reason) {
  const rt = util.readRuntime(root);
  if (rt.mihomo_pid && pidAlive(rt.mihomo_pid) && await pidPathOwned(rt.mihomo_pid, root)) {
    await killMihomo(rt.mihomo_pid, rt.api_port, rt.secret);
    lines.push('Cleaned up: half-started kernel terminated (pid ' + rt.mihomo_pid + ')');
  }
  if (rt.watcher_pid && pidAlive(rt.watcher_pid)) {
    const wk = await killWatcher(rt, root, lines);
    if (wk) lines.push('Cleaned up: watcher terminated (pid ' + rt.watcher_pid + ')');
  }
  util.writeRuntimeAtomic(root, s => {
    s.state = 'stopped'; s.intent = 'stop'; s.last_error = reason;
  });
  lines.push('Start failed: ' + reason);
}

async function cmdStart() {
  const root = util.skillRoot();
  const P = util.paths();
  const lines = [];
  ensureVarDirs();

  // 前置①：内核存在（§2 时序①）
  if (!fs.existsSync(P.kernelExe)) {
    lines.push('Kernel binary not found: bin/mihomo.exe');
    lines.push('Run: node scripts/vpn.js bootstrap');
    return { lines, json: { state: 'kernel-missing' }, rc: 1 };
  }

  // 前置②：幂等检查（§4：已运行→返回现状 rc=0）+ 心跳维度收殓（§3.4，t3 启用）
  const rt = util.readRuntime(root);
  if ((rt.state === 'running' || rt.state === 'degraded') && rt.mihomo_pid && pidAlive(rt.mihomo_pid)) {
    const owned = await pidPathOwned(rt.mihomo_pid, root);
    const ver = owned ? await apiRequest(rt.api_port, rt.secret, 'GET', '/version', 1500) : null;
    if (owned && ver && ver.status === 200) {
      const hbAge = Math.floor(Date.now() / 1000) - (rt.heartbeat_ts || 0);
      if (hbAge <= 120) {
        // watcher 心跳新鲜 → 真运行中
        const ps = await poolStats(rt.api_port, rt.secret);
        lines.push('Already running (mihomo pid ' + rt.mihomo_pid + ', watcher pid ' + (rt.watcher_pid || 'n/a') + ')');
        lines.push('Proxy port: ' + rt.proxy_port);
        lines.push('Prefix: ' + util.envPrefixLine(rt.proxy_port));
        return {
          lines, rc: 0,
          json: { state: 'running', proxy_port: rt.proxy_port, api_port: rt.api_port,
            mihomo_pid: rt.mihomo_pid, watcher_pid: rt.watcher_pid || null,
            watcher_heartbeat_age_s: hbAge, pool_total: ps ? ps.pool_total : null, already_running: true },
        };
      }
      // mihomo 应答但心跳超 120s：watcher 死、mihomo 孤儿 → 收殓后走全新启动（§3.4）
      await reapByHeartbeat(root, rt, lines);
    }
    // 状态失真（进程死/路径异/无应答）→ 交孤儿扫描收殓后走全新启动
  } else if (rt.state === 'starting' &&
             rt.heartbeat_ts && Math.floor(Date.now() / 1000) - rt.heartbeat_ts <= 60) {
    // 上一 start 的 watcher 仍在启动窗口（探针 15s+余量）：不重复启动
    lines.push('Start already in progress (state=starting); run status to check');
    return { lines, rc: 0, json: { state: 'starting', note: 'start-in-progress' } };
  }

  // 前置③：孤儿扫描收殓（§3.4 惰性清理；§4.1 损坏恢复兜底——runtime 失真/损坏场景）
  const reaped = await reapOrphans(root, lines);

  // 步骤①：免费源首拉（§2 数据流①；单源失败已在 providers 内降级写空池占位，
  // 此处 catch 的是 sources.yaml 缺失等安装级异常——警告后继续，config 按实存轨道生成）
  let refreshSummary = null;
  try {
    const r = await providers.refreshAll();
    refreshSummary = { ok: r.okCount, failed: r.failCount };
    lines.push('Free sources refreshed: ' + r.okCount + ' ok, ' + r.failCount + ' failed');
  } catch (e) {
    lines.push('Warning: free source prefetch failed: ' + (e && e.message ? e.message : 'unknown'));
  }

  // 步骤②：试绑定端口（§3.6；候选生成器硬编码排除 7890/9090）
  const proxyPort = await util.findFreePort(util.PROXY_PORT_CANDIDATES);
  const apiPort = await util.findFreePort(util.API_PORT_CANDIDATES);
  if (!proxyPort || !apiPort) {
    lines.push('No free port in candidate ranges (7891-7900 / 9091-9100)');
    return { lines, json: { state: 'port-exhausted', reaped }, rc: 1 };
  }
  lines.push('Ports: proxy=' + proxyPort + ' api=' + apiPort);

  // 完整 config 生成（t2 收口点：findFreePort 实得端口传参注入）
  const secret = crypto.randomBytes(16).toString('hex');
  let gen;
  try {
    gen = config.generate({ mixedPort: proxyPort, apiPort, secret });
  } catch (e) {
    lines.push('Config generation failed: ' + (e && e.message ? e.message : 'unknown'));
    return { lines, json: { state: 'start-failed', reason: 'config-error' }, rc: 1 };
  }
  lines.push('Config generated: ' + gen.providerCount + ' providers');

  // 步骤③：runtime 预写（watcher 由此读 api_port/secret 拉起 mihomo）。
  // 保险丝参数仅缺失时写默认、不覆盖既有值（参数 runtime.json 可调——测试调短加速后
  // 重跑 start 不应被重置回默认 600s）
  const now = Math.floor(Date.now() / 1000);
  util.writeRuntimeAtomic(root, s => {
    s.state = 'starting';
    s.intent = 'start';
    s.proxy_port = proxyPort;
    s.api_port = apiPort;
    s.secret = secret;
    s.mihomo_pid = null;
    s.watcher_pid = null;
    s.watcher_start_ts = null;
    s.heartbeat_ts = now;
    s.speed_up_bps = null;
    s.speed_down_bps = null;
    s.idle_s = null;
    s.degraded = false;
    s.fuse_reason = null;
    s.fuse_ts = null;
    s.start_ts = now;
    s.last_error = null;
    s.reaper = null; // 新启动清除历史收殓标记（该标记由 reapByHeartbeat 写、watcher exit 消费）
    if (!Number.isFinite(s.idle_window_s)) s.idle_window_s = 600;
    if (!Number.isFinite(s.idle_threshold)) s.idle_threshold = 1024;
    if (!Number.isFinite(s.burst_allow)) s.burst_allow = 3;
  });

  // 步骤④：detached+unref spawn watcher（process.execPath 起 watcher.js，stdio ignore——
  // watcher 自身不产出 stdout；独立于 CLI 存续，mihomo 管道由 watcher 持有消费）
  const watcherJs = path.join(root, 'scripts', 'lib', 'watcher.js');
  const wchild = spawn(process.execPath, [watcherJs],
    { detached: true, stdio: 'ignore', windowsHide: true });
  wchild.unref();
  // watcher 身份因子写 runtime（killWatcher 校验依据：CIM CreationDate，spawn 后采集一次）
  const ident = await watcherIdentity(wchild.pid, root);
  util.writeRuntimeAtomic(root, s => {
    s.watcher_pid = wchild.pid;
    s.watcher_start_ts = ident && ident.creationTs !== null ? ident.creationTs : null;
  });
  lines.push('Watcher spawned: pid ' + wchild.pid);

  // 步骤⑤：CLI 等就绪信号（watcher 探针过→写 state=running；或写 stopped=watcher 已自清理）
  const deadline = Date.now() + 15000;
  let ready = false;
  let failReason = null;
  while (Date.now() < deadline) {
    await sleep(300);
    const cur = util.readRuntime(root);
    if (cur.state === 'running' && cur.mihomo_pid) { ready = true; break; }
    if (cur.state === 'stopped') { failReason = cur.last_error || 'watcher-start-failed'; break; }
  }
  if (!ready) {
    const reason = failReason || 'start_timeout';
    await cleanupStartFailure(root, lines, reason);
    return {
      lines, rc: 1,
      json: { state: 'start-failed', reason, proxy_port: proxyPort, api_port: apiPort },
    };
  }

  // 步骤⑥：成功输出
  const rt2 = util.readRuntime(root);
  const ps = await poolStats(apiPort, secret);
  lines.push('Kernel ready (via watcher): mihomo pid ' + rt2.mihomo_pid);
  lines.push('Started: prefix template ->');
  lines.push(util.envPrefixLine(proxyPort));
  return {
    lines, rc: 0,
    json: { state: 'running', proxy_port: proxyPort, api_port: apiPort,
      mihomo_pid: rt2.mihomo_pid, watcher_pid: rt2.watcher_pid,
      pool_total: ps ? ps.pool_total : null,
      sources_ok: refreshSummary ? refreshSummary.ok : null,
      sources_failed: refreshSummary ? refreshSummary.failed : null, reaped },
  };
}

// ---------- 子命令：stop（§3.4 优雅停，t3 扩展双方进程；§4 幂等：未运行→rc=0） ----------
// 序列：①写 intent=stop（watcher exit handler 据此识别手动停，不写 mihomo-exit 噪声）
// ②mihomo 双校验+killMihomo（DELETE /connections→taskkill）③watcher 经互守自退——
// mihomo 死触发其 exit handler 自退；短等未退才强杀（PID+身份双因子校验，R3）
async function cmdStop() {
  const root = util.skillRoot();
  const lines = [];
  const rt = util.readRuntime(root);
  const out = { state: 'stopped', killed_pid: null, watcher_killed: null };

  const runningish = rt.state === 'running' || rt.state === 'starting' || rt.state === 'degraded';
  const mihomoAlive = rt.mihomo_pid && pidAlive(rt.mihomo_pid);

  if (!runningish && !mihomoAlive) {
    // 完全未运行（t1 幂等路径）；仅清可能的 watcher 残留（如熔断竞态窗口）
    if (rt.watcher_pid && pidAlive(rt.watcher_pid)) {
      out.watcher_killed = await killWatcher(rt, root, lines);
    }
    lines.push('Not running');
    return { lines, json: out, rc: 0 };
  }

  // ①声明停机意图（watcher exit handler 的 manual-stop 判据）
  util.writeRuntimeAtomic(root, s => { s.intent = 'stop'; });

  // ②mihomo 优雅停（R3 双校验：exe 不在 skill bin/ 内绝不杀）
  if (mihomoAlive) {
    const owned = await pidPathOwned(rt.mihomo_pid, root);
    if (!owned) {
      util.writeRuntimeAtomic(root, s => {
        s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'pid-path-mismatch';
      });
      lines.push('Warning: mihomo pid ' + rt.mihomo_pid + ' exe outside skill bin/ -- NOT killed (safety check)');
      lines.push('State file reset to stopped');
      return { lines, json: Object.assign(out, { note: 'pid-path-mismatch-not-killed' }), rc: 2 };
    }
    await killMihomo(rt.mihomo_pid, rt.api_port, rt.secret);
    out.killed_pid = rt.mihomo_pid;
    lines.push('Stopped kernel: pid ' + rt.mihomo_pid);
  } else {
    lines.push('Kernel process already gone');
  }

  // ③watcher：互守自退优先（mihomo 死→其 exit handler 自退）；≤3s 未退才强杀（校验后）
  if (rt.watcher_pid && pidAlive(rt.watcher_pid)) {
    let exited = false;
    for (let i = 0; i < 10 && pidAlive(rt.watcher_pid); i++) await sleep(300);
    if (!pidAlive(rt.watcher_pid)) exited = true;
    else exited = await killWatcher(rt, root, lines);
    out.watcher_killed = exited;
    lines.push(exited ? 'Watcher exited'
      : 'Warning: watcher still alive (identity unverified, left to mutual guard)');
  }

  // ④终态（watcher 可能已写过 stopped；此处幂等覆写为 manual-stop 终态，清 fuse/reaper 标记）
  util.writeRuntimeAtomic(root, s => {
    s.state = 'stopped'; s.intent = 'stop'; s.last_error = null; s.fuse_reason = null; s.reaper = null;
  });
  return { lines, json: out, rc: 0 };
}

// ---------- 子命令：restart（§4：stop+start 组合，幂等——stopped 下等价直接 start） ----------
async function cmdRestart() {
  const stopRes = await cmdStop();
  const startRes = await cmdStart();
  const lines = [...stopRes.lines, ...startRes.lines];
  const json = Object.assign({}, startRes.json, {
    restarted: true,
    stop_killed_pid: (stopRes.json && stopRes.json.killed_pid) || null,
    stop_rc: stopRes.rc,
  });
  // rc：start 失败优先；start 成功而 stop 带警告（如 pid-path-mismatch）→ 2
  const rc = startRes.rc !== 0 ? startRes.rc : (stopRes.rc === 2 ? 2 : 0);
  return { lines, json, rc };
}

// ---------- 子命令：status（§4；t3 扩展：watcher 心跳+degraded+心跳维度收殓） ----------
// 注：心跳维度收殓（mihomo 应答但心跳超 120s → 收殓）按任务书 t3 规格执行——与设计 §4
// 「纯只读」表述冲突，从任务书（§3.4 惰性清理原文「任何 CLI 子命令启动时」）；报告已注明
async function cmdStatus() {
  const root = util.skillRoot();
  const lines = [];
  const rt = util.readRuntime(root);
  const out = {
    // state 报告「实际观察值」：探活成功才报 running/degraded（陈旧标记场景报 stopped+note）
    state: 'stopped', proxy_port: null, current_node: null, pool_total: null, pool_alive: null,
    uptime_s: null, idle_s: null, speed_up_bps: null, speed_down_bps: null, degraded: false,
    watcher_heartbeat_age_s: null, watcher_dead: null,
  };

  if ((rt.state === 'running' || rt.state === 'degraded') && rt.mihomo_pid && pidAlive(rt.mihomo_pid)) {
    const owned = await pidPathOwned(rt.mihomo_pid, root);
    const ver = owned ? await apiRequest(rt.api_port, rt.secret, 'GET', '/version', 1500) : null;
    if (owned && ver && ver.status === 200) {
      const hbAge = Math.floor(Date.now() / 1000) - (rt.heartbeat_ts || 0);
      out.watcher_heartbeat_age_s = hbAge;
      out.watcher_dead = hbAge > 120;
      if (out.watcher_dead) {
        // §3.4 惰性收殓（心跳维度，t3）：mihomo 活+/version 应答但 watcher 心跳超 120s
        // → watcher 死、mihomo 孤儿 → 收殓（killMihomo+清状态）
        await reapByHeartbeat(root, rt, lines);
        out.state = 'stopped';
        out.reaped = 'watcher-dead';
        return { lines, json: out, rc: 0 };
      }
      out.state = rt.state;
      out.proxy_port = rt.proxy_port;
      const ps = await poolStats(rt.api_port, rt.secret);
      if (ps) { out.current_node = ps.current_node; out.pool_total = ps.pool_total; out.pool_alive = ps.pool_alive; }
      if (rt.start_ts) out.uptime_s = Math.max(0, Math.floor(Date.now() / 1000) - rt.start_ts);
      out.speed_up_bps = rt.speed_up_bps === undefined ? null : rt.speed_up_bps;
      out.speed_down_bps = rt.speed_down_bps === undefined ? null : rt.speed_down_bps;
      out.idle_s = rt.idle_s === undefined ? null : rt.idle_s; // watcher /traffic 采样维护（t3）
      out.degraded = rt.degraded === true;
      lines.push('Running: mihomo pid ' + rt.mihomo_pid + ' (watcher pid ' + (rt.watcher_pid || 'n/a') +
        ', heartbeat ' + hbAge + 's ago) proxy_port ' + rt.proxy_port);
      lines.push('Prefix: ' + util.envPrefixLine(rt.proxy_port));
    } else {
      // runtime 声称 running 但探活失败：只读报告实际状态（陈旧标记），不修文件
      out.note = 'stale-runtime-probe-failed';
      lines.push('State file says running, but process probe failed -- treating as stopped (read-only)');
    }
  } else if (rt.state === 'starting') {
    out.state = 'starting';
    lines.push('Starting (watcher bootstrapping kernel)');
  } else {
    lines.push('Stopped');
    if (rt.last_error) lines.push('Last error: ' + rt.last_error);
    if (rt.fuse_reason) lines.push('Fuse reason: ' + rt.fuse_reason + ' at ' + new Date((rt.fuse_ts || 0) * 1000).toISOString());
  }
  return { lines, json: out, rc: 0 };
}

module.exports = {
  cmdStart,
  cmdStop,
  cmdRestart,
  cmdStatus,
  // 可移交 watcher / 供测试驱动的编程接口
  spawnCore,
  buildMinimalConfig,
  ensureFixture,
  apiRequest,
  waitVersion,
  pidAlive,
  pidPathOwned,
  exePathOfPid,
  killMihomo,
  reapOrphans,
  netstatListenPids,
  // t3 新增：watcher 进程管理与心跳维度收殓
  watcherIdentity,
  killWatcher,
  reapByHeartbeat,
};
