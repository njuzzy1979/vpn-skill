/**
 * cmd-doctor.js — doctor 子命令 handler（设计 §4 / §3.5）
 *
 * 诊断七项（逐项 {name, ok, detail}）：
 *  1 kernel      bin/mihomo.exe 存在 + kernel.json 可解析（版本/通道；运行中附 /version 一致性）
 *  2 ports       候选两段（7891-7900/9091-9100）监听态：运行中=登记端口在听；
 *                未运行=段内应无自家残留（外部占用仅提示，start 会漂移）
 *  3 processes   mihomo + watcher 进程与心跳 age；未运行时区分「刚被熔断」
 *                （fuse_reason + fuse_ts 新鲜 → 预期态，t3 遗留 2 的语义细化）
 *  4 sources     三免费源 × 三通道首字节可达性探测（R2：失败明细只含截断 host）
 *  5 pool        /proxies/POOL total/alive（未运行 n/a；alive=0 → POOL:EMPTY 诊断）
 *  6 sub-providers 订阅 provider 拉取状态：GET /providers/proxies 取 vehicleType=HTTP 项，
 *                失败签名=updatedAt 零时刻(0001-01-01)+0 节点（本批实测字段形态，[D4]；
 *                无真订阅环境下假订阅显示失败状态本身即正确诊断形态）
 *  7 runtime     var/runtime.json 存在 + 可解析 + 基本字段
 *
 * 自动清理（复用 core 收殓，幂等——清完再跑=全 ok）：心跳超时收殓（reapByHeartbeat）、
 * 停机态自家端口残留（reapOrphans）、停机态 watcher 残留（killWatcher，身份校验）、
 * 陈旧 running 标记复位。绝不清非自家进程（R3：路径/身份双校验在 core 层）。
 *
 * 输出协议：英文 ASCII 行 + ===JSON=== + 单行 JSON（节点名不入人类行；无 URL 回显）。
 * 退出码：0=全部 ok / 1=有 fail / 2=全 ok 但发生修复。
 */

'use strict';

const fs = require('fs');
const https = require('https');

const util = require('./util');
const api = require('./api');
const core = require('./core');
const providers = require('./providers');
const bootstrap = require('./bootstrap'); // M2：latest 比对复用其通道池（bootstrap 不依赖 cmd-doctor，无环）

const SOURCE_PROBE_TIMEOUT_MS = 6000;
const RECENT_FUSE_S = 600; // 「刚被熔断」判定窗：10 分钟内 fuse 视为预期终态

/**
 * 输出协议：英文行 + ===JSON=== + 单行 JSON（与 cmd-update 同构）
 */
function emitResult(lines, obj) {
  for (const l of lines) console.log(l);
  console.log('===JSON===');
  console.log(JSON.stringify(obj));
}

// ---------- 免费源通道首字节探测（doctor 专用轻探针：GET 后首字节即断，不拉全量） ----------

/**
 * 首字节探测：任何状态码都算可达（含 4xx/5xx——能应答即网络通）。
 * @returns {Promise<{ok:boolean, status:number|null, ms:number, reason:string|null}>}
 *          reason 为 ASCII 短原因（超时/连接失败等，不含 URL）
 */
function probeFirstByte(urlStr, timeoutMs) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let u;
    try { u = new URL(urlStr); } catch (e) { return resolve({ ok: false, status: null, ms: 0, reason: 'invalid-url' }); }
    if (u.protocol !== 'https:') return resolve({ ok: false, status: null, ms: 0, reason: 'https-only' });
    let settled = false;
    const req = https.request({
      hostname: u.hostname, port: u.port || 443,
      path: u.pathname + u.search, method: 'GET',
      headers: { 'User-Agent': 'vpn-skill-doctor', Accept: '*/*' },
      timeout: timeoutMs,
    }, res => {
      // 首字节探测：拿到首个 data（或空响应体直接 end）即判成功并立刻断开。
      // 注意不能 destroy 后再等 end——destroyed 流不再 emit end，Promise 会永悬
      const done = () => {
        if (settled) return;
        settled = true;
        const r = { ok: true, status: res.statusCode, ms: Date.now() - t0, reason: null };
        try { req.destroy(); } catch (e) { /* 已断 */ }
        resolve(r);
      };
      res.once('data', done);
      res.once('end', done);
      res.resume();
    });
    req.on('timeout', () => {
      if (settled) return;
      settled = true;
      try { req.destroy(); } catch (e) { /* 已断 */ }
      resolve({ ok: false, status: null, ms: Date.now() - t0, reason: 'timeout' });
    });
    req.on('error', e => {
      if (settled) return; // 主动 destroy 触发的错误：结果已定，忽略
      settled = true;
      resolve({ ok: false, status: null, ms: Date.now() - t0, reason: (e && e.message ? String(e.message).slice(0, 60) : 'error') });
    });
    req.end();
  });
}

/**
 * 三源 × 三通道探测。每源任一通道可达即 ok（与 providers 降级语义一致）。
 * detail 形如：ermaozi: direct ok(210ms); jsdelivr FAIL(timeout); ghproxy ok(180ms)
 * 失败通道附截断 host（R2，providers.maskUrl）。
 */
async function checkSources(lines) {
  const srcDoc = providers.readYamlFile(providers.paths.sourcesFile);
  if (!srcDoc || !Array.isArray(srcDoc.sources) || srcDoc.sources.length === 0) {
    return { name: 'sources', ok: false, detail: 'user/sources.yaml missing or empty (skill install broken)' };
  }
  const parts = [];
  let allOk = true;
  for (const s of srcDoc.sources) {
    const channels = s.channels || {};
    const chNames = Object.keys(channels);
    const probes = await Promise.all(chNames.map(ch => probeFirstByte(channels[ch], SOURCE_PROBE_TIMEOUT_MS)));
    let srcOk = false;
    const chParts = [];
    chNames.forEach((ch, i) => {
      const p = probes[i];
      if (p.ok) { srcOk = true; chParts.push(ch + ' ok(' + p.ms + 'ms)'); }
      else chParts.push(ch + ' FAIL[' + providers.maskUrl(channels[ch]) + ' ' + p.reason + ']');
    });
    if (!srcOk) allOk = false;
    parts.push(s.name + ': ' + chParts.join('; '));
  }
  const detail = parts.join(' | ');
  lines.push((allOk ? '[ok] ' : '[FAIL] ') + 'sources: ' + (allOk ? 'all reachable' : 'some source unreachable on all channels'));
  return { name: 'sources', ok: allOk, detail };
}

// ---------- doctor 主流程 ----------

/**
 * doctor handler
 * @param {string[]} argv（当前无参数）
 * @returns {Promise<number>} 退出码
 */
async function handle(argv) {
  if (argv && argv.length) {
    emitResult(['error: doctor takes no arguments'], { checks: [], repaired: [], error: 'bad-argument' });
    return 1;
  }
  const root = util.skillRoot();
  const P = util.paths();
  const lines = [];
  const checks = [];
  const repaired = [];

  // ---- runtime 原始读取（区分 缺失/损坏/正常，readRuntime 会把前两者都归 {}） ----
  let rtExists = false;
  let rtParseable = false;
  let rt = {};
  try {
    const raw = fs.readFileSync(P.runtimeJson, 'utf8');
    rtExists = true;
    rt = JSON.parse(raw);
    if (rt && typeof rt === 'object' && !Array.isArray(rt)) rtParseable = true; else rt = {};
  } catch (e) {
    if (e && e.code === 'ENOENT') rtExists = false; // 缺失
    else rtExists = true;                            // 存在但损坏
  }

  // ---- 评估运行态（先于检查：修复决策依赖评估结果） ----
  const nowS = Math.floor(Date.now() / 1000);
  const hbAge = rt.heartbeat_ts ? (nowS - rt.heartbeat_ts) : null;
  const stateRunningish = rt.state === 'running' || rt.state === 'degraded';
  const isStarting = rt.state === 'starting' && hbAge !== null && hbAge <= 60;

  let mihomoAlive = false;
  let mihomoOwned = false;
  let version = null;
  if (stateRunningish && rt.mihomo_pid && core.pidAlive(rt.mihomo_pid)) {
    mihomoAlive = true;
    mihomoOwned = await core.pidPathOwned(rt.mihomo_pid, root);
    if (mihomoOwned) version = await api.getVersion(rt.api_port, rt.secret);
  }
  let running = mihomoAlive && mihomoOwned && version !== null;

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  // R4（两路共用）：停机态 watcher 残留——互守应自退；短等未退才身份校验后清
  async function repairWatcherResidual() {
    const rtNow = util.readRuntime(root);
    if (!rtNow.watcher_pid || !core.pidAlive(rtNow.watcher_pid)) return;
    for (let i = 0; i < 7 && core.pidAlive(rtNow.watcher_pid); i++) await sleep(300); // ≤2.1s 等互守自退
    if (!core.pidAlive(rtNow.watcher_pid)) return;
    const wk = await core.killWatcher(rtNow, root, lines);
    if (wk) {
      repaired.push({ action: 'kill-residual-watcher', pid: rtNow.watcher_pid });
      lines.push('Repaired: killed residual watcher (pid ' + rtNow.watcher_pid + ')');
    } else {
      lines.push('Warning: residual watcher pid ' + rtNow.watcher_pid + ' not killed (identity unverified)');
    }
  }

  // ---- 自动清理（M1：op_lock 互斥，§2 时序③——与 watcher 刷新并发时让路，仅诊断） ----
  const lockOwner = 'doctor-' + process.pid;
  const lockAcquired = util.acquireOpLock(root, lockOwner);
  let cleanupSkippedByLock = null;
  if (!lockAcquired) {
    const holder = rt.op_lock && typeof rt.op_lock === 'object' ? String(rt.op_lock.owner) : 'unknown';
    cleanupSkippedByLock = holder;
    lines.push('Cleanup skipped: op_lock held by ' + holder + ' -- diagnosis only (rerun doctor after it releases)');
  }
  try {
    // R1 心跳收殓（§3.4）：mihomo 活+自家+API 应答 但 watcher 心跳超 120s → 收殓。
    // 该场景本身就是「运行中 watcher 死」形态，独立于停机态门；starting 窗口内不触发
    let reapedByHeartbeat = false;
    if (lockAcquired && mihomoAlive && mihomoOwned && version && hbAge !== null && hbAge > 120 && !isStarting) {
      await core.reapByHeartbeat(root, rt, lines);
      reapedByHeartbeat = true;
      running = false;
      mihomoAlive = false;
      repaired.push({ action: 'reap-heartbeat-stale-kernel', pid: rt.mihomo_pid, heartbeat_age_s: hbAge });
      lines.push('Repaired: reaped heartbeat-stale kernel (pid ' + rt.mihomo_pid + ')');
    }

    if (lockAcquired && !running && !isStarting && !reapedByHeartbeat) {
      // R2：runtime 声称 running 但内核死/失应答 → 陈旧标记复位（含 mihomo 活但 API 死的挂起态）
      if (stateRunningish && !(mihomoAlive && mihomoOwned && version)) {
        if (mihomoAlive && mihomoOwned) {
          await core.killMihomo(rt.mihomo_pid, rt.api_port, rt.secret);
          mihomoAlive = false;
          repaired.push({ action: 'kill-unresponsive-kernel', pid: rt.mihomo_pid });
          lines.push('Repaired: killed unresponsive kernel (pid ' + rt.mihomo_pid + ', API no answer)');
        }
        util.writeRuntimeAtomic(root, s => {
          s.state = 'stopped'; s.intent = 'stop'; s.last_error = 'doctor-stale-state-reset';
        });
        repaired.push({ action: 'reset-stale-runtime-state', from: rt.state });
        lines.push('Repaired: stale runtime state ' + JSON.stringify(rt.state) + ' reset to stopped');
      }
      // R3：停机态自家端口残留收殓（reapOrphans 内部做 PID+路径双校验，R3）
      const reapedPorts = await core.reapOrphans(root, lines);
      for (const r of reapedPorts) {
        repaired.push({ action: 'reap-orphan-kernel', port: r.port, pid: r.pid });
        lines.push('Repaired: reaped orphan kernel on port ' + r.port + ' (pid ' + r.pid + ')');
      }
      // R4
      await repairWatcherResidual();
    } else if (reapedByHeartbeat) {
      // R1 已写正确终态（last_error=watcher-dead-reaped），不复位状态防覆盖诊断；
      // 真 watcher 若未随 mihomo 之死自退（假死形态），R4 兜底
      await repairWatcherResidual();
    }
  } finally {
    if (lockAcquired) util.releaseOpLock(root, lockOwner);
  }

  // ---- 检查 1：kernel（含 M2：经 bootstrap 通道池比对官方 latest，§3.1/§13） ----
  {
    let ok = true;
    const parts = [];
    const exeOk = fs.existsSync(P.kernelExe);
    let kj = null;
    try { kj = JSON.parse(fs.readFileSync(P.kernelJson, 'utf8')); } catch (e) { kj = null; }
    if (!exeOk) { ok = false; parts.push('bin/mihomo.exe MISSING (run bootstrap)'); }
    if (!kj) { ok = false; parts.push('kernel.json missing or unparseable'); }
    else parts.push('binary ' + (exeOk ? 'present' : 'missing') + ', recorded ' + kj.version + ' (' + kj.channel + ')');
    if (version && kj && kj.version && kj.version !== version) {
      ok = false; // 运行版本与记录不一致：升级后未重启/回滚态——按 fail 呈现（需 restart 收敛）
      parts.push('RUNNING ' + version + ' != recorded ' + kj.version + ' (restart after upgrade?)');
    } else if (version) parts.push('running ' + version + ' matches');

    // M2：官方 latest 比对（经通道池；探测失败降级为本地比对+警告行，不阻塞诊断、不改 rc）
    const kernelCheck = { name: 'kernel', ok, detail: null };
    if (kj && kj.version) {
      const latest = await bootstrap.fetchLatestTag();
      if (latest) {
        kernelCheck.latest_version = latest.tag;
        if (latest.tag !== kj.version) {
          kernelCheck.update_available = true;
          parts.push('upstream latest ' + latest.tag);
          lines.push('[warn] kernel update available: ' + kj.version + ' -> ' + latest.tag + ' (run: stop, then bootstrap)');
        } else {
          kernelCheck.update_available = false;
          parts.push('up to date (upstream latest ' + latest.tag + ')');
        }
      } else {
        lines.push('[warn] kernel update check unavailable (all channels failed) -- local check only');
      }
    }
    kernelCheck.detail = parts.join('; ');
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'kernel: ' + kernelCheck.detail);
    checks.push(kernelCheck);
  }

  // ---- 检查 2：ports ----
  {
    const ports = [...util.PROXY_PORT_CANDIDATES, ...util.API_PORT_CANDIDATES];
    const pidMap = await core.netstatListenPids();
    const held = ports.filter(p => pidMap.has(p));
    let ok = true;
    let detail;
    if (running) {
      const proxyOk = pidMap.has(rt.proxy_port);
      const apiOk = pidMap.has(rt.api_port);
      ok = proxyOk && apiOk;
      detail = 'registered proxy ' + rt.proxy_port + (proxyOk ? ' listening' : ' NOT listening') +
        ', api ' + rt.api_port + (apiOk ? ' listening' : ' NOT listening');
      const extra = held.filter(p => p !== rt.proxy_port && p !== rt.api_port);
      if (extra.length) detail += '; other segment listeners: ' + extra.join(',');
    } else if (held.length === 0) {
      detail = 'no listeners in candidate segments (7891-7900/9091-9100) -- clean';
    } else {
      // 剩余监听者未被收殓=非自家进程（外部占用）：skill 会漂移端口，非故障但如实报告
      detail = 'segment ports ' + held.join(',') + ' held by outside processes (pid ' +
        held.map(p => pidMap.get(p)).join(',') + '); start will drift to a free port';
    }
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'ports: ' + detail);
    checks.push({ name: 'ports', ok, detail });
  }

  // ---- 检查 3：processes（含「刚被熔断」语义区分，t3 遗留 2） ----
  {
    let ok = true;
    let detail;
    const rtNow = util.readRuntime(root);
    if (running) {
      const hAge = rtNow.heartbeat_ts ? (nowS - rtNow.heartbeat_ts) : null;
      const wAlive = rtNow.watcher_pid ? core.pidAlive(rtNow.watcher_pid) : false;
      ok = hAge !== null && hAge <= 120 && wAlive;
      detail = 'mihomo pid ' + rt.mihomo_pid + ' alive, watcher pid ' + rtNow.watcher_pid +
        (wAlive ? ' alive' : ' DEAD') + ', heartbeat ' + (hAge === null ? 'none' : hAge + 's ago');
      if (!ok) detail += ' -- watcher side unhealthy' + (hAge !== null && hAge > 120 ? ' (heartbeat stale >120s)' : '');
    } else if (isStarting) {
      detail = 'starting (watcher bootstrapping kernel, heartbeat ' + (hbAge === null ? 'none' : hbAge + 's ago') + ')';
    } else {
      // 停机态：区分「刚被熔断」（预期）与普通停止/异常
      const fuseAge = rtNow.fuse_ts ? nowS - rtNow.fuse_ts : null;
      if (rtNow.state === 'stopped' && rtNow.fuse_reason && fuseAge !== null && fuseAge <= RECENT_FUSE_S) {
        detail = 'stopped by fuse \'' + rtNow.fuse_reason + '\' ' + fuseAge + 's ago -- expected idle shutdown, not an anomaly';
      } else if (rtNow.state === 'stopped') {
        detail = 'stopped' + (rtNow.last_error ? ' (last_error=' + rtNow.last_error + ')' : '') +
          (rtNow.fuse_reason ? ' (fuse=' + rtNow.fuse_reason + ' ' + (fuseAge === null ? '?' : Math.floor(fuseAge / 60) + 'min') + ' ago)' : '');
      } else {
        detail = 'kernel not running (runtime state=' + JSON.stringify(rtNow.state) + ')';
      }
      const stray = rtNow.mihomo_pid && core.pidAlive(rtNow.mihomo_pid);
      if (stray) { ok = false; detail += '; mihomo pid ' + rtNow.mihomo_pid + ' still alive unexpectedly'; }
    }
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'processes: ' + detail);
    checks.push({ name: 'processes', ok, detail });
  }

  // ---- 检查 4：sources（三源三通道首字节探测） ----
  checks.push(await checkSources(lines));

  // ---- 检查 5：pool ----
  {
    let ok = true;
    let detail;
    if (running) {
      // alive 统计需全量 /proxies（组对象只有 all/now；alive 标记在逐节点条目上）
      const pj = await api.getProxies(rt.api_port, rt.secret);
      const g = pj && pj.proxies && pj.proxies.POOL ? pj.proxies.POOL : null;
      if (!g || !Array.isArray(g.all)) {
        ok = false; detail = 'POOL group not retrievable from API';
      } else {
        let alive = 0;
        for (const nm of g.all) if (pj.proxies[nm] && pj.proxies[nm].alive) alive++;
        if (alive === 0) { ok = false; detail = 'POOL:EMPTY -- total ' + g.all.length + ', alive 0 (all nodes dead; run update, then retest)'; }
        else detail = 'total ' + g.all.length + ', alive ' + alive;
      }
    } else {
      detail = 'kernel stopped -- pool n/a (run start)';
    }
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'pool: ' + detail);
    checks.push({ name: 'pool', ok, detail });
  }

  // ---- 检查 6：sub-providers（订阅 provider 拉取状态；R2 不回显 URL） ----
  {
    let ok = true;
    let detail;
    if (running) {
      const r = await api.requestJson(rt.api_port, rt.secret, 'GET', '/providers/proxies', 5000);
      if (!r || r.status !== 200 || !r.json || !r.json.providers) {
        ok = false; detail = '/providers/proxies not retrievable';
      } else {
        const subs = Object.values(r.json.providers).filter(p => p && p.vehicleType === 'HTTP');
        if (subs.length === 0) {
          detail = 'no subscription provider configured (setup --sub <URL> to add)';
        } else {
          const parts = [];
          for (const p of subs) {
            const nodes = Array.isArray(p.proxies) ? p.proxies.length : 0;
            // 失败签名（实测）：updatedAt 零时刻 + 0 节点 = 从未成功拉取（[D4]）
            const ts = new Date(p.updatedAt || 0).getTime();
            const never = !Number.isFinite(ts) || ts <= 0;
            if (never || nodes === 0) {
              ok = false;
              parts.push(p.name + ': FETCH FAILED (' + (never ? 'never updated' : 'updatedAt ' + p.updatedAt) +
                ', ' + nodes + ' nodes) -- user action: check/replace subscription');
            } else {
              parts.push(p.name + ': ok (' + nodes + ' nodes, updated ' + new Date(ts).toISOString() + ')');
            }
          }
          detail = parts.join('; ');
        }
      }
    } else {
      detail = 'kernel stopped -- subscription providers n/a (diagnose while running)';
    }
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'sub-providers: ' + detail);
    checks.push({ name: 'sub-providers', ok, detail });
  }

  // ---- 检查 7：runtime（重读最新快照——上方修复可能已改写状态） ----
  {
    let ok = true;
    let detail;
    if (!rtExists) {
      ok = false; detail = 'var/runtime.json missing (fresh install or never started; start will create it)';
    } else if (!rtParseable) {
      ok = false; detail = 'var/runtime.json unparseable (will be treated as no-state; start re-probes and rebuilds)';
    } else {
      const rtFresh = util.readRuntime(root);
      detail = 'parseable, state=' + rtFresh.state + ', write_seq=' + (rtFresh.write_seq || 0);
      if (rtFresh.state === 'running' && (!rtFresh.proxy_port || !rtFresh.mihomo_pid)) {
        ok = false; detail += ' -- running state missing port/pid fields';
      }
    }
    lines.push((ok ? '[ok] ' : '[FAIL] ') + 'runtime: ' + detail);
    checks.push({ name: 'runtime', ok, detail });
  }

  const failCount = checks.filter(c => !c.ok).length;
  const rc = failCount > 0 ? 1 : (repaired.length > 0 ? 2 : 0);
  lines.unshift('Doctor: ' + checks.length + ' checks, ' + failCount + ' failed, ' + repaired.length + ' repaired');
  const out = {
    state: running ? 'running' : (isStarting ? 'starting' : util.readRuntime(root).state || 'stopped'),
    checks, repaired,
  };
  if (cleanupSkippedByLock !== null) out.cleanup_skipped = 'op_lock held by ' + cleanupSkippedByLock;
  emitResult(lines, out);
  return rc;
}

module.exports = { handle };
