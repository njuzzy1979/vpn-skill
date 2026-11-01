// util.js — vpn-skill 公共工具：路径解析（§13 可移植）、端口候选与试绑定（§3.6）、
// 日志脱敏两层规则（§7 R2）、runtime.json 原子写协议（§4.1）、CLI 输出协议（§4/§8）
'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');

// ---------- 路径解析（§13：一切基于 __dirname 向上定位 skill 根，禁止绝对路径硬编码） ----------

let _rootCache = null;
function skillRoot() {
  if (_rootCache) return _rootCache;
  // 本文件位于 <skill根>/scripts/lib/，向上两级；用 scripts/vpn.js 存在性校验布局，防目录被挪动后误判
  const root = path.resolve(__dirname, '..', '..');
  if (!fs.existsSync(path.join(root, 'scripts', 'vpn.js'))) {
    throw new Error('skill root layout broken: scripts/vpn.js not found above lib/');
  }
  _rootCache = root;
  return root;
}

// skill 内标准路径集合（单点维护，供各模块引用）
function paths() {
  const root = skillRoot();
  return {
    root,
    bin: path.join(root, 'bin'),
    kernelExe: path.join(root, 'bin', 'mihomo.exe'),
    kernelJson: path.join(root, 'kernel.json'),
    varDir: path.join(root, 'var'),
    varConfig: path.join(root, 'var', 'config.yaml'),
    varProviders: path.join(root, 'var', 'providers'),
    varLogs: path.join(root, 'var', 'logs'),
    mihomoLog: path.join(root, 'var', 'logs', 'mihomo.log'),
    runtimeJson: path.join(root, 'var', 'runtime.json'),
  };
}

// ---------- 端口策略（§3.6） ----------

// R3 铁律：候选生成器硬编码排除 FlClash 段 {7890, 9090}（防御性冗余——两段基址天然不含，集合再挡一层）
const EXCLUDED_PORTS = new Set([7890, 9090]);
function _range(a, b) { const r = []; for (let i = a; i <= b; i++) r.push(i); return r; }
const PROXY_PORT_CANDIDATES = _range(7891, 7900).filter(p => !EXCLUDED_PORTS.has(p)); // 代理端口 10 个
const API_PORT_CANDIDATES = _range(9091, 9100).filter(p => !EXCLUDED_PORTS.has(p));   // API 端口 10 个

// 试绑定（§3.6：net.createServer EADDRINUSE 即占，Node 生态通行实践）——返回首个可绑定端口或 null
function findFreePort(candidates) {
  return new Promise(resolve => {
    const tryNext = i => {
      if (i >= candidates.length) return resolve(null);
      const srv = net.createServer();
      srv.once('error', () => tryNext(i + 1));            // EADDRINUSE 等：占，试下一个
      srv.once('listening', () => srv.close(() => resolve(candidates[i])));
      srv.listen(candidates[i], '127.0.0.1');
    };
    tryNext(0);
  });
}

// TCP 端口连通探测（bootstrap 通道③用：判断 127.0.0.1:7890 是否有本机代理在听）
function probeTcpPort(port, timeoutMs) {
  return new Promise(resolve => {
    const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); });
    s.setTimeout(timeoutMs || 1500, () => { s.destroy(); resolve(false); });
    s.on('error', () => resolve(false));
  });
}

// ---------- 日志脱敏（§7 R2：两层规则，mihomo.log 落盘前必经） ----------

// 占位符：订阅完整 URL → <SUBSCRIPTION>；其余已知凭据值（token 等）→ <CREDENTIAL>
const PLACEHOLDER = { subscription: '<SUBSCRIPTION>', credential: '<CREDENTIAL>' };

// 第二层：模式正则兜底（不依赖已知值）
// - URL 查询参数形态：保留参数名打码值
// - yaml 冒号形态（LR1 复审项）：保留键名，行内值打码；已被第一层替换的 <占位符> 值跳过，避免吞掉标记
// - 节点 URI：保留协议名整体打码
// - HTTP 认证头：Bearer 后凭据打码
const PATTERN_RULES = [
  [/([?&](token|password|secret|key|uuid|auth)=)[^&\s"']+/gi, (m, p1) => p1 + '***'],
  [/\b(token|password|secret|key|uuid)\s*:\s*(\S+)/gi, (m, k, v) => (v && v.startsWith('<') ? m : k + ': ***')],
  [/\b(vmess|vless|trojan|ss):\/\/\S+/gi, (m, p1) => p1 + '://***'],
  [/\bBearer\s+\S+/gi, () => 'Bearer ***'],
];

// sanitize(line, knownSecrets)：单行脱敏。knownSecrets = [{value, kind:'subscription'|'credential'}, ...]
// 第一层已知子串替换在前（长值优先，防短子串先替换导致长 URL 命中失败），第二层模式兜底在后
// 容错归一：纯字符串元素自动升格为 {value, kind:'credential'}——形态传错时静默 filter 掉
// 会使第一层脱敏无声失效（凭据直落盘，H1 同族风险），归一化是防御纵深而非便利
function sanitize(line, knownSecrets) {
  let out = line;
  const list = (knownSecrets || [])
    .map(s => (typeof s === 'string' ? { value: s, kind: 'credential' } : s))
    .filter(s => s && typeof s.value === 'string' && s.value.length >= 6)
    .sort((a, b) => b.value.length - a.value.length);
  for (const s of list) {
    out = out.split(s.value).join(PLACEHOLDER[s.kind] || PLACEHOLDER.credential);
  }
  for (const [re, rep] of PATTERN_RULES) out = out.replace(re, rep);
  return out;
}

// ---------- runtime.json 读写协议（§4.1 写者矩阵 + 写协议） ----------

// 读快照；缺失/损坏/非对象一律返回 {}（§4.1 损坏恢复：按无运行态处理，t1 由 start 前孤儿扫描兜底）
function readRuntime(root) {
  try {
    const raw = fs.readFileSync(path.join(root, 'var', 'runtime.json'), 'utf8');
    const obj = JSON.parse(raw);
    return (obj && typeof obj === 'object' && !Array.isArray(obj)) ? obj : {};
  } catch (e) {
    return {};
  }
}

// 原子条件写：①读快照记 write_seq → ②mutator 仅改本写者字段 → ③tmp+rename 前校验磁盘 write_seq 未变
// → ④不等则重读合并重试 ≤3 次（§4.1 写协议；失败放弃本次写，由调用方记录，不 crash）
function writeRuntimeAtomic(root, mutator) {
  const file = path.join(root, 'var', 'runtime.json');
  const tmp = file + '.tmp';
  fs.mkdirSync(path.dirname(file), { recursive: true });
  for (let attempt = 0; attempt < 3; attempt++) {
    const snap = readRuntime(root);
    const draft = JSON.parse(JSON.stringify(snap));
    if (!draft.version) draft.version = 1; // L4：schema 版本锚
    mutator(draft);
    const disk = readRuntime(root);
    if ((disk.write_seq || 0) !== (snap.write_seq || 0)) continue; // 他写者已推进：重读合并重试
    draft.write_seq = (snap.write_seq || 0) + 1;
    try {
      fs.writeFileSync(tmp, JSON.stringify(draft, null, 2) + '\n', 'utf8');
      fs.renameSync(tmp, file);
      return true;
    } catch (e) {
      // Windows 下 rename 偶发占用冲突：进入下一次重试
    }
  }
  return false;
}

// ---------- op_lock 互斥（§2 时序③ / §4.1 字段表：doctor 自动清理与 watcher 刷新不并发） ----------
// 语义：{owner, ts} 写入 runtime.json；持锁判定=ts 距今 <10s 且 owner 非本人 → 被占。
// 设计约束：获取失败**立即让路**（不等待、不重试——互斥不得引入死锁/长等待）；
// 10s 超时自然过期（持锁方崩溃后无需显式释放）。与 write_seq 条件写正交：
// 条件写防数据丢失，op_lock 防行为交叠（验证报告 M1：两者不可互相替代）。

const OP_LOCK_STALE_S = 10; // §4.1：超时 10s 视弃锁

function lockHeldByOther(lock, owner, now) {
  return !!(lock && typeof lock === 'object' && lock.owner !== owner &&
    Number.isFinite(lock.ts) && (now - lock.ts) < OP_LOCK_STALE_S);
}

/**
 * 获取 op_lock：无锁/过期/本人持有 → 条件写抢占 {owner, ts}；被他方新鲜持有 → false。
 * mutator 内二次校验收窄并发窗口（两方同时通过前置读时，write_seq 条件写+复检只放行一方）。
 * @returns {boolean} 是否取得锁
 */
function acquireOpLock(root, owner) {
  const now = Math.floor(Date.now() / 1000);
  if (lockHeldByOther(readRuntime(root).op_lock, owner, now)) return false; // 快路径：被占立即让路
  let granted = false;
  const ok = writeRuntimeAtomic(root, s => {
    if (lockHeldByOther(s.op_lock, owner, now)) return; // 并发窗口内被他方抢先：不写字段（让路）
    s.op_lock = { owner, ts: now };
    granted = true;
  });
  return ok && granted;
}

/**
 * 释放 op_lock：仅当锁仍是本人的才清（防误释放他方锁）。释放失败无副作用（10s 自然过期兜底）。
 */
function releaseOpLock(root, owner) {
  writeRuntimeAtomic(root, s => {
    if (s.op_lock && typeof s.op_lock === 'object' && s.op_lock.owner === owner) s.op_lock = null;
  });
}

// ---------- 日志落盘 ----------

// 追加一行到日志文件（已脱敏内容；UTF-8）。t1 由 core 直接调用，t3 移交 watcher 后仍走本函数
function appendLogLine(logFile, line) {
  try {
    fs.appendFileSync(logFile, line + '\n', 'utf8');
  } catch (e) {
    // 日志写失败不反噬内核生命周期（§3.4 watcher 死亡窗口同思路：丢日志不影响代理功能）
  }
}

// ---------- CLI 输出协议（§4：人类行=纯英文 ASCII + ===JSON=== 尾块单行 JSON；§8 GBK 控制台直视安全） ----------

// 非 ASCII 字符统一折叠为 '?'——人类行恒 GBK 直视安全
function toAscii(s) {
  return String(s).replace(/[^\x20-\x7E]/g, '?');
}

// JSON 尾块：单行 JSON。注：JSON 行不经 toAscii——机器解析块，节点名等 UTF-8 经 Git Bash 管道安全（r1 §7）
function emitResult(lines, json, rc) {
  for (const l of (lines || [])) console.log(toAscii(l));
  console.log('===JSON===');
  console.log(JSON.stringify(json === undefined ? {} : json));
  process.exit(rc === undefined ? 0 : rc);
}

// §3.3 代理注入模板行（start/status 输出拼好的前缀，Claude 按命令粒度复制）
function envPrefixLine(proxyPort) {
  return 'HTTP_PROXY=http://127.0.0.1:' + proxyPort +
    ' HTTPS_PROXY=http://127.0.0.1:' + proxyPort +
    ' ALL_PROXY=http://127.0.0.1:' + proxyPort +
    ' NODE_USE_ENV_PROXY=1 <command>';
}

// buildKnownSecrets(urls)：订阅 URL → 三粒度子串集（完整 URL / 去 query 前缀 / host）。
// 三粒度缺一不可：内核日志中订阅地址以三种形态出现——provider 拉取错误（完整 URL）、
// TCP 连接日志（host:port）。只给完整 URL 会使 host 形态凭据明文落盘（D1 实测）。
function buildKnownSecrets(urls) {
  const out = [];
  for (const u of (urls || [])) {
    if (typeof u !== 'string' || u.length < 6) continue;
    out.push({ value: u, kind: 'subscription' });
    const qi = u.indexOf('?');
    if (qi > 0) out.push({ value: u.slice(0, qi), kind: 'subscription' });
    try {
      const h = new URL(u).host; // host 形态（TCP 日志 `host:port`）
      if (h && h.length >= 4) out.push({ value: h, kind: 'subscription' });
    } catch (e) { /* 非法 URL 跳过 host 粒度 */ }
  }
  return out;
}

module.exports = {
  skillRoot,
  paths,
  EXCLUDED_PORTS,
  PROXY_PORT_CANDIDATES,
  API_PORT_CANDIDATES,
  findFreePort,
  probeTcpPort,
  sanitize,
  buildKnownSecrets,
  readRuntime,
  writeRuntimeAtomic,
  acquireOpLock,
  releaseOpLock,
  appendLogLine,
  toAscii,
  emitResult,
  envPrefixLine,
};
