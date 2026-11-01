#!/usr/bin/env node
/**
 * watcher.js — 常驻守护（设计 §3.4 保险丝 A+C 组合的主轴；§2 组件表）
 *
 * 由 cmdStart 以 detached+unref 拉起（t1 关键实测：本环境 node 非 detached 子进程
 * 随父退出被立即收割——watcher 必须 detached 才能独立于 CLI 存续），职责：
 *  1. mihomo 生命周期：spawnCore(detached:false) 父子互守（§8）——mihomo 死→本进程
 *     写终态自退；本进程死→mihomo 成孤儿交 CLI 惰性收殓（心跳维度，§3.4）
 *  2. 日志管道消费：spawnCore onLogLine 注入点=脱敏落盘 var/logs/mihomo.log（§7 R2，
 *     t1「CLI 退出丢运行期日志」缺口就此关闭）；自身事件写 var/logs/watcher.log——
 *     白名单制：仅 ISO 时间/级别/事件/统计量，绝不写 URL/凭据/节点名
 *  3. 保险丝（§3.4 空闲分支）：/traffic 流式样本 → 滑动窗口判定（idle_window_s/
 *     idle_threshold/burst_allow 读 runtime.json，心跳周期热读——测试调参无需重启）
 *     → 辅助校验 /connections 活跃数=0 → 熔断：优雅停 mihomo → 写终态
 *     state=stopped + fuse_reason=idle + fuse_ts → 自退
 *  4. 心跳：每 30s writeRuntimeAtomic 写 heartbeat_ts + 最近速率采样
 *     speed_up_bps/speed_down_bps + idle_s（§4.1 写者矩阵；CLI status 消费）
 *  5. 免费源定时刷新：小时级（§2 组件表）；独立异常边界（L5）——try/catch 包裹，
 *     失败仅记 watcher.log 不中断保险丝主循环
 *  6. degraded 标记：池全挂（pool_total>0 且 alive==0）写 runtime.degraded（§3.5）
 *
 * 写协议：一切 runtime 写经 util.writeRuntimeAtomic（§4.1——仅改本写者字段）。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const util = require('./util');
const core = require('./core');
const api = require('./api');
const providers = require('./providers');
const config = require('./config');
const exportTop = require('./export-top').exportTop; // t7：定时刷新成功后自动导出延迟 Top N

const root = util.skillRoot();
const P = util.paths();
const WATCHER_LOG = path.join(P.varLogs, 'watcher.log');
const HEARTBEAT_MS = 30 * 1000;        // 心跳周期（§4.1）
const REFRESH_MS = 60 * 60 * 1000;     // 免费源刷新周期：小时级（§2 组件表）

// ---------- watcher.log 白名单日志（§7 R2：仅时间/级别/事件/统计量） ----------
// fields 只允许统计量与枚举值；任何外部来源文本（异常 message 等）入 detail 前必经
// util.sanitize 且截长——免费源失败明细已在 providers 层 maskUrl 截断 host
function wlog(level, event, fields) {
  const parts = [new Date().toISOString(), level, 'event=' + event];
  for (const k of Object.keys(fields || {})) {
    const v = fields[k];
    if (v === undefined || v === null) continue;
    parts.push(k + '=' + String(v));
  }
  util.appendLogLine(WATCHER_LOG, parts.join(' '));
}

// ---------- 运行态（本守护生命周期内的单例上下文） ----------
const ctx = {
  apiPort: null,
  secret: null,
  mihomoPid: null,
  latest: null,        // 最近 /traffic 样本（心跳速率采样）
  samples: [],         // 滑动窗口样本 {t, bps}
  lastBusyTs: 0,       // 最近超阈样本时刻（idle_s 计算基准；ready 时初始化为启动时刻）
  lastAuxCheck: 0,     // /connections 辅助校验节流
  fuse: { windowS: 600, threshold: 1024, burst: 3 }, // §3.4 默认；runtime 可调
  fusing: false,       // 熔断进行中（mihomo exit handler 据此让出终态写权）
  exiting: false,
  traffic: null,       // /traffic 流 controller
};

function nowS() { return Math.floor(Date.now() / 1000); }

// 保险丝参数热读（runtime.json 可调——§3.4「参数入 runtime.json 可调，测试时缩短加速」）
function refreshFuseParams() {
  const rt = util.readRuntime(root);
  const w = Number(rt.idle_window_s);
  if (Number.isFinite(w) && w > 0) ctx.fuse.windowS = w;
  const t = Number(rt.idle_threshold);
  if (Number.isFinite(t) && t > 0) ctx.fuse.threshold = t;
  const b = Number(rt.burst_allow);
  if (Number.isFinite(b) && b >= 0) ctx.fuse.burst = b;
}

function idleSeconds() {
  if (!ctx.lastBusyTs) return null;
  return Math.max(0, Math.floor((Date.now() - ctx.lastBusyTs) / 1000));
}

// ---------- 保险丝主判定（§3.4 空闲分支） ----------
// 滑动窗口：窗口满（覆盖 ≥90% idle_window_s）且窗口内超阈样本 ≤ burst_allow
// （容忍 health-check 噪声尖峰）→ 空闲候选 → 辅助校验 /connections 活跃数=0 → 熔断。
// /traffic 每秒一样本（up/down 单位 bytes/s），up+down 与阈值（默认 1KB/s）比较。
function onTrafficSample(s) {
  ctx.latest = s;
  const bps = s.up + s.down;
  ctx.samples.push({ t: s.t, bps });
  if (bps >= ctx.fuse.threshold) ctx.lastBusyTs = s.t;
  const horizon = s.t - ctx.fuse.windowS * 1000;
  while (ctx.samples.length && ctx.samples[0].t < horizon) ctx.samples.shift();
  if (ctx.samples.length < 5) return; // 样本过少不判
  const spanMs = ctx.samples[ctx.samples.length - 1].t - ctx.samples[0].t;
  if (spanMs < ctx.fuse.windowS * 1000 * 0.9) return; // 窗口未满不判
  let over = 0;
  for (const smp of ctx.samples) if (smp.bps >= ctx.fuse.threshold) over++;
  if (over > ctx.fuse.burst) return; // 超阈次数多 = 明显有流量
  // 空闲候选成立 → 辅助校验（5s 节流，防判定堆积；fire-and-forget）
  if (Date.now() - ctx.lastAuxCheck < 5000) return;
  ctx.lastAuxCheck = Date.now();
  auxCheck().catch(() => { /* auxCheck 内部自容错，此处双保险 */ });
}

// 辅助校验：活跃连接数=0 才熔断（排除长连接静默挂起误判，§3.4）
async function auxCheck() {
  if (ctx.fusing || ctx.exiting) return;
  const c = await api.getConnections(ctx.apiPort, ctx.secret);
  if (!c) return; // API 不可达：保守不熔断（下轮样本重判）
  if (c.activeCount !== 0) return;
  await tripFuse('idle');
}

// ---------- 熔断（§3.4「熔断终态写权」：watcher 有权写终态） ----------
async function tripFuse(reason) {
  if (ctx.fusing || ctx.exiting) return;
  ctx.fusing = true; // mihomo exit handler 见此标记让出终态写权（防 fuse 终态被 mihomo-exit 覆盖）
  wlog('warn', 'fuse-trip', {
    reason, window_s: ctx.fuse.windowS, threshold_bps: ctx.fuse.threshold, burst_allow: ctx.fuse.burst,
  });
  if (ctx.traffic) ctx.traffic.stop();
  // 优雅停（§3.4）：killMihomo 内部先 DELETE /connections 清连接再 taskkill
  if (ctx.mihomoPid && core.pidAlive(ctx.mihomoPid)) {
    await core.killMihomo(ctx.mihomoPid, ctx.apiPort, ctx.secret);
  }
  await waitMihomoExit(3000);
  const ok = util.writeRuntimeAtomic(root, s => {
    s.state = 'stopped';
    s.intent = 'stop';
    s.fuse_reason = reason;
    s.fuse_ts = nowS();
    s.last_error = null;
    s.speed_up_bps = null;
    s.speed_down_bps = null;
    s.idle_s = null;
  });
  if (!ok) wlog('error', 'fuse-terminal-write-failed', {});
  wlog('info', 'watcher-exit', { reason: 'fuse-' + reason, mihomo_pid: ctx.mihomoPid });
  process.exit(0);
}

function waitMihomoExit(timeoutMs) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const tick = () => {
      if (!ctx.mihomoPid || !core.pidAlive(ctx.mihomoPid)) return resolve();
      if (Date.now() - t0 >= timeoutMs) return resolve();
      setTimeout(tick, 200);
    };
    tick();
  });
}

// mihomo 退出处置（互守的 watcher 侧）：非熔断/非手动路径 → 写终态自退
// 三态区分（t3 遗留 1，t4 收口）：manual-stop（cmdStop 写 intent=stop）/
// reaped-heartbeat（CLI 收殓写 reaper=heartbeat-stale——本进程曾假死被收殓）/
// mihomo-exit（内核自身异常退出）；watcher.log 事件标签与此一一对应
function onMihomoExit(code, signal) {
  if (ctx.fusing || ctx.exiting) return; // 熔断/manual/兜底路径已自处置
  ctx.exiting = true;
  const rt = util.readRuntime(root);
  const manual = rt.intent === 'stop';            // cmdStop 先写 intent=stop：属预期退出，不标 last_error
  const reaped = rt.reaper === 'heartbeat-stale'; // 心跳收殓杀死（watcher 假死场景），非用户手动
  util.writeRuntimeAtomic(root, s => {
    s.state = 'stopped';
    s.intent = 'stop';
    if (!manual && !reaped) s.last_error = 'mihomo-exit';
    if (reaped) s.reaper = null; // 消费即清：防标记残留误标后续手动停
  });
  const reason = reaped ? 'reaped-heartbeat' : (manual ? 'manual-stop' : 'mihomo-exit');
  wlog('info', 'watcher-exit', { reason, code, signal });
  process.exit(0);
}

// ---------- 心跳（§4.1 写者矩阵：heartbeat_ts / speed_up_bps / speed_down_bps） ----------
// 顺带：热读保险丝参数 + degraded 判定（§3.5：池全挂标 degraded，status 可见）
async function heartbeatTick() {
  try {
    refreshFuseParams();
    let degraded = null;
    const pj = await api.getProxies(ctx.apiPort, ctx.secret);
    if (pj && pj.proxies && pj.proxies.POOL && Array.isArray(pj.proxies.POOL.all)) {
      let alive = 0;
      for (const nm of pj.proxies.POOL.all) { if (pj.proxies[nm] && pj.proxies[nm].alive) alive++; }
      degraded = pj.proxies.POOL.all.length > 0 && alive === 0;
    }
    const ok = util.writeRuntimeAtomic(root, s => {
      s.heartbeat_ts = nowS();
      s.speed_up_bps = ctx.latest ? Math.round(ctx.latest.up) : null;
      s.speed_down_bps = ctx.latest ? Math.round(ctx.latest.down) : null;
      s.idle_s = idleSeconds();
      if (degraded !== null) s.degraded = degraded;
    });
    if (!ok) wlog('warn', 'heartbeat-write-failed', {});
  } catch (e) {
    wlog('warn', 'heartbeat-error', { detail: util.sanitize(String(e && e.message || e)).slice(0, 100) });
  }
}

// ---------- 免费源定时刷新（独立异常边界 L5：失败只记日志，绝不中断保险丝主循环） ----------
// M1（§2 时序③）：刷新与 doctor 自动清理经 op_lock 互斥——被占则本轮跳过（下轮再试，
// 小时级周期损失一轮无影响）；获取失败立即让路，不等待
async function refreshTick() {
  if (!util.acquireOpLock(root, 'watcher-refresh')) {
    wlog('info', 'refresh-skipped-lock', {});
    return;
  }
  try {
    const r = await providers.refreshAll();
    wlog('info', 'source-refresh', { ok: r.okCount, failed: r.failCount });
    // 热更（§3.2：PUT /providers/proxies/:name 全量——sub + free）
    if (ctx.mihomoPid && core.pidAlive(ctx.mihomoPid)) {
      const entries = config.listProviderEntries();
      let updated = 0;
      for (const e of entries) {
        if (await api.putProvider(ctx.apiPort, ctx.secret, e.name)) updated++;
      }
      wlog('info', 'providers-hot-reload', { updated, total: entries.length });
      // t7 自动导出：刷新/热更有成果 → 延迟 Top N。独立异常边界（同 L5 思路）：
      // 导出失败仅记 watcher.log（白名单统计量），绝不影响刷新主循环与保险丝
      if (r.okCount > 0 || updated > 0) {
        try {
          const ex = await exportTop({ apiPort: ctx.apiPort, secret: ctx.secret });
          if (ex) wlog('info', 'export-top', { exported: ex.exported, total: ex.total_candidates });
          else wlog('warn', 'export-failed', { detail: 'kernel-not-responding' });
        } catch (e) {
          wlog('warn', 'export-failed', { detail: util.sanitize(String(e && e.message || e)).slice(0, 120) });
        }
      }
    }
  } catch (e) {
    // 刷新异常仅记日志（消息经 sanitize；providers 层失败明细已 maskUrl 截断 host）
    wlog('warn', 'refresh-failed', { detail: util.sanitize(String(e && e.message || e)).slice(0, 120) });
  } finally {
    util.releaseOpLock(root, 'watcher-refresh');
  }
}

// ---------- 主流程 ----------
async function main() {
  fs.mkdirSync(P.varLogs, { recursive: true });
  const rt = util.readRuntime(root);
  ctx.apiPort = rt.api_port;
  ctx.secret = rt.secret;
  if (!ctx.apiPort || !ctx.secret) {
    // CLI 预写缺失（异常启动）：写终态自退，CLI 侧 15s 超时清理兜底
    util.writeRuntimeAtomic(root, s => {
      s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'watcher-missing-runtime';
    });
    process.exit(1);
  }
  refreshFuseParams();

  // knownSecrets（§7 两层脱敏的第一层输入）：订阅 URL 三粒度展开 + 本实例 API secret。
  // 假订阅同样在 user/subscriptions.yaml 里——照常构建（任务书：假订阅也在文件里，照常）
  const subUrls = [];
  const subs = providers.readYamlFile(path.join(root, 'user', 'subscriptions.yaml'));
  if (subs && Array.isArray(subs.subscriptions)) {
    for (const s of subs.subscriptions) if (s && typeof s.url === 'string') subUrls.push(s.url);
  }
  const knownSecrets = util.buildKnownSecrets(subUrls).concat([{ value: ctx.secret, kind: 'credential' }]);

  wlog('info', 'watcher-start', {
    pid: process.pid, api_port: ctx.apiPort,
    window_s: ctx.fuse.windowS, threshold_bps: ctx.fuse.threshold, burst_allow: ctx.fuse.burst,
  });

  // ① spawn mihomo：detached:false 父子互守（§8）；stdio pipe 由本进程消费
  //    （spawnCore 默认 onLogLine=脱敏落盘 mihomo.log，t1 运行期日志缺口就此关闭）
  const spawned = core.spawnCore(root, { detached: false, knownSecrets });
  ctx.mihomoPid = spawned.pid;
  spawned.child.on('error', e => {
    ctx.exiting = true;
    util.writeRuntimeAtomic(root, s => {
      s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'mihomo-spawn-error';
    });
    wlog('error', 'watcher-exit', {
      reason: 'mihomo-spawn-error',
      detail: util.sanitize(String(e && e.message || e)).slice(0, 100),
    });
    process.exit(1);
  });
  spawned.child.on('exit', onMihomoExit);

  // ② 就绪探针（§2⑤，15s；失败→失败清理序列：kill 半启内核→终态→自退）
  const version = await core.waitVersion(ctx.apiPort, ctx.secret, 15000);
  if (!version) {
    ctx.exiting = true; // 让出 exit handler 的终态写权，保留 start_timeout 语义
    await core.killMihomo(ctx.mihomoPid, ctx.apiPort, ctx.secret);
    util.writeRuntimeAtomic(root, s => {
      s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'start_timeout';
    });
    wlog('error', 'watcher-exit', { reason: 'start-timeout' });
    process.exit(1);
  }

  // ③ 就绪：写 running 终态字段（CLI 轮询 state=running 作为就绪信号）
  ctx.lastBusyTs = Date.now(); // idle_s 基准初始化（尚无样本时不报 null）
  util.writeRuntimeAtomic(root, s => {
    s.state = 'running';
    s.mihomo_pid = ctx.mihomoPid;
    s.watcher_pid = process.pid;
    s.heartbeat_ts = nowS();
    s.degraded = false;
  });
  wlog('info', 'mihomo-ready', { mihomo_pid: ctx.mihomoPid, version });

  // ④ 主循环构件：/traffic 流（保险丝数据源）+ 心跳 + 定时刷新。
  //    首次刷新安排在下个整周期——CLI start 已做首拉，避免立即重复。
  //    timer 与长连接共同持有 event loop，watcher 常驻。
  ctx.traffic = api.openTrafficStream({
    port: ctx.apiPort,
    secret: ctx.secret,
    onSample: onTrafficSample,
    onEvent: kind => { if (kind === 'retry') wlog('warn', 'traffic-stream-retry', {}); },
  });
  setInterval(heartbeatTick, HEARTBEAT_MS);
  setInterval(refreshTick, REFRESH_MS);
  wlog('info', 'watcher-loop-started', { heartbeat_s: HEARTBEAT_MS / 1000, refresh_s: REFRESH_MS / 1000 });
}

// 兜底：未捕获异常 → 白名单记日志 + 尽力杀 mihomo（防孤儿空转）+ 自退。
// 杀失败也不重试——mihomo 孤儿由 CLI 惰性收殓兜底（§3.4 风险缓解）
process.on('uncaughtException', e => {
  try { wlog('error', 'watcher-fatal', { detail: util.sanitize(String(e && e.message || e)).slice(0, 120) }); } catch (_) { /* 日志失败不救 */ }
  try {
    if (ctx.mihomoPid && core.pidAlive(ctx.mihomoPid)) {
      const t = setTimeout(() => process.exit(1), 2000);
      t.unref();
      core.killMihomo(ctx.mihomoPid, ctx.apiPort, ctx.secret)
        .catch(() => {})
        .then(() => { clearTimeout(t); process.exit(1); });
    } else {
      process.exit(1);
    }
  } catch (_) { process.exit(1); }
});

main().catch(e => {
  try {
    wlog('error', 'watcher-main-failed', { detail: util.sanitize(String(e && e.message || e)).slice(0, 120) });
    // 仅当尚未 running 才写终态（避免覆盖已成功启动后的偶发异常路径状态）
    util.writeRuntimeAtomic(root, s => {
      if (s.state !== 'running') { s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'watcher-main-failed'; }
    });
  } catch (_) { /* 尽力而为 */ }
  process.exit(1);
});
