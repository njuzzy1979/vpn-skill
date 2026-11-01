/**
 * cmd-test.js — test 子命令 handler（设计 §4）
 *
 * 行为：
 *  - 默认（无参数 / [url]）：经 mixed-port 代理端口发一次真实请求。
 *    https 走 node 内置 http CONNECT 隧道（自包含，不依赖系统 curl，§8）；
 *    http 走代理绝对形态 GET。默认 URL gstatic generate_204。
 *  - --all：触发组测速 GET /group/POOL/delay?url=...&timeout=5000
 *    （url-test 组无固定选择，无清除选择副作用，§4），输出最快 5 节点 + 当前节点延迟。
 *    注：池数千节点时组测速需数十秒级等待，属内核并发实测的固有耗时。
 *
 * 输出协议：英文 ASCII 人类行（节点名只入 JSON 尾块——§8 GBK 控制台直视安全）
 *           + ===JSON=== + 单行 JSON。
 * 退出码：0=连通（拿到 HTTP 应答 / 组测速有节点应答） / 1=失败（未运行/隧道失败/全超时）。
 *
 * R2：本命令不回显任何订阅 URL；节点名按设计 §4 允许出现在输出（日志层不落）。
 */

'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');

const util = require('./util');
const api = require('./api');

const DEFAULT_TEST_URL = 'https://www.gstatic.com/generate_204';
const GROUP_NAME = 'POOL';
// 组测速 timeout 参数实测语义（2026-11-01，mihomo v1.19.33，池 5396 节点）：它是**整个组测试
// 的总 deadline** 而非单节点超时——设计 §4 原值 5000ms 下 5396 节点必 504 all-timeout
// （5s 内并发测不完）；60000ms 实测 200 且返回窗口内应答的全部节点（部分结果语义）。
// 小池（百级）不受影响。按 [VERIFY] 实测结论取 60000。
const GROUP_DELAY_TIMEOUT_MS = 60000;
const GROUP_DELAY_CLIENT_MS = 180000;  // 客户端等待上限：内核应在 deadline 内应答，留余量
const TOP_N = 5;

/**
 * 输出协议：英文行 + ===JSON=== + 单行 JSON（与 cmd-update 同构）
 */
function emitResult(lines, obj) {
  for (const l of lines) console.log(l);
  console.log('===JSON===');
  console.log(JSON.stringify(obj));
}

/**
 * https 经代理 CONNECT 隧道单次请求：CONNECT → TLS 握手 → 写 HTTP/1.1 GET → 读状态行。
 * 首字节即可判连通（204 无响应体），读至状态行即断开。
 * @returns {Promise<{status:number, ms:number}>} 失败 reject（Error.message 为 ASCII 原因）
 */
function fetchHttpsViaConnect(proxyPort, urlStr, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const host = u.hostname;
    const port = u.port || 443;
    const t0 = Date.now();
    const req = http.request({
      host: '127.0.0.1', port: proxyPort, method: 'CONNECT',
      path: host + ':' + port, timeout: timeoutMs,
      headers: { Host: host + ':' + port },
    });
    const fail = (msg) => { try { req.destroy(); } catch (e) { /* 已断 */ } reject(new Error(msg)); };
    req.on('timeout', () => fail('connect tunnel timeout after ' + timeoutMs + 'ms'));
    req.on('error', e => fail('tunnel error: ' + (e.message || 'unknown')));
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); fail('tunnel refused: ' + res.statusCode); return; }
      const tlsSock = tls.connect({ socket, servername: host }, () => {
        const path = u.pathname + u.search;
        tlsSock.write('GET ' + (path || '/') + ' HTTP/1.1\r\nHost: ' + host +
          '\r\nUser-Agent: vpn-skill-test\r\nAccept: */*\r\nConnection: close\r\n\r\n');
        let buf = '';
        const onTick = () => {
          const idx = buf.indexOf('\r\n');
          if (idx < 0) {
            if (buf.length > 8192) { cleanup(); reject(new Error('status line too large')); }
            return; // 状态行未完整，继续等
          }
          const m = buf.slice(0, idx).match(/^HTTP\/\d\.\d (\d{3})/);
          cleanup();
          if (!m) { reject(new Error('malformed status line')); return; }
          resolve({ status: Number(m[1]), ms: Date.now() - t0 });
        };
        const onData = (c) => { buf += c; onTick(); };
        const cleanup = () => {
          tlsSock.removeListener('data', onData);
          try { tlsSock.destroy(); } catch (e) { /* 已断 */ }
        };
        const onErr = () => { cleanup(); reject(new Error('tls read error')); };
        tlsSock.on('data', onData);
        tlsSock.once('error', onErr);
      });
      tlsSock.once('error', e => fail('tls handshake error: ' + (e.message || 'unknown')));
    });
    req.end();
  });
}

/**
 * http 经代理绝对形态 GET（代理对 http 请求直接转发绝对 URI）
 * @returns {Promise<{status:number, ms:number}>}
 */
function fetchHttpViaProxy(proxyPort, urlStr, timeoutMs) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const u = new URL(urlStr);
    const req = http.request({
      host: '127.0.0.1', port: proxyPort, method: 'GET',
      path: urlStr, timeout: timeoutMs,
      headers: { Host: u.host, 'User-Agent': 'vpn-skill-test', Accept: '*/*' },
    }, res => {
      res.resume(); // 只关心状态码
      res.once('data', () => { try { req.destroy(); } catch (e) { /* 已断 */ } });
      resolve({ status: res.statusCode, ms: Date.now() - t0 });
    });
    req.on('timeout', () => { try { req.destroy(); } catch (e) { /* 已断 */ } reject(new Error('request timeout after ' + timeoutMs + 'ms')); });
    req.on('error', e => { try { req.destroy(); } catch (e2) { /* 已断 */ } reject(new Error('request error: ' + (e.message || 'unknown'))); });
    req.end();
  });
}

/**
 * 组测速（--all）：GET /group/POOL/delay。200 → {节点名: 延迟ms} 映射（deadline 内应答的
 * 部分结果）；全超时 → 504 + {"message":"get delay: all proxies timeout"}（实测形态）。
 * timeout 参数=组测试总 deadline（见文件头实测注释），非单节点超时。
 * @returns {Promise<{ok:boolean, map:Object|null, ms:number, reason:string|null}>}
 */
async function groupDelay(apiPort, secret, testUrl) {
  const t0 = Date.now();
  const p = '/group/' + encodeURIComponent(GROUP_NAME) + '/delay?url=' +
    encodeURIComponent(testUrl) + '&timeout=' + GROUP_DELAY_TIMEOUT_MS;
  const r = await api.request(apiPort, secret, 'GET', p, GROUP_DELAY_CLIENT_MS);
  if (!r) return { ok: false, map: null, ms: Date.now() - t0, reason: 'api-no-answer' };
  if (r.status === 200 && r.body) {
    try {
      const j = JSON.parse(r.body);
      if (j && typeof j === 'object' && !Array.isArray(j)) {
        return { ok: true, map: j, ms: Date.now() - t0, reason: null };
      }
    } catch (e) { /* 落入下方 malformed */ }
    return { ok: false, map: null, ms: Date.now() - t0, reason: 'malformed-response' };
  }
  // 504 等错误形态：body 可含 message 字段（实测：all proxies timeout）
  let reason = 'api-status-' + r.status;
  try {
    const j = JSON.parse(r.body || '{}');
    if (j && typeof j.message === 'string') reason += ': ' + j.message;
  } catch (e) { /* 保持状态码形态 */ }
  return { ok: false, map: null, ms: Date.now() - t0, reason };
}

/**
 * test handler
 * @param {string[]} argv ['--all'] / ['<url>'] / ['<url>', '--all'] / []
 * @returns {Promise<number>} 退出码
 */
async function handle(argv) {
  const lines = [];
  let url = DEFAULT_TEST_URL;
  let all = false;
  for (const a of argv) {
    if (a === '--all') { all = true; continue; }
    if (/^https?:\/\//i.test(a)) { url = a; continue; }
    emitResult(['error: bad argument: ' + a + ' (expected [url] and/or --all)'], { url: null, delay_ms: null, via_node: null, error: 'bad-argument' });
    return 1;
  }

  // 运行态读取（容错：缺失/损坏按 {} → 视为未运行）
  const root = util.skillRoot();
  const rt = util.readRuntime(root);
  const running = (rt.state === 'running' || rt.state === 'degraded') && rt.proxy_port;
  if (!running) {
    emitResult(['Not running -- start first (node vpn.js start)'], { url, delay_ms: null, via_node: null, error: 'not-running' });
    return 1;
  }

  // 当前节点（尽力而为：组信息不可得时 via_node=null，不阻塞连通测试本身）
  const grp = await api.getGroup(rt.api_port, rt.secret, GROUP_NAME);
  const viaNode = grp && typeof grp.now === 'string' ? grp.now : null;

  if (!all) {
    // ---- 默认：单次真实请求经代理端口 ----
    let r;
    try {
      r = url.startsWith('http://')
        ? await fetchHttpViaProxy(rt.proxy_port, url, 15000)
        : await fetchHttpsViaConnect(rt.proxy_port, url, 15000);
    } catch (e) {
      lines.push('Proxy test FAILED: ' + (e.message || 'unknown'));
      if (viaNode) lines.push('Current node was: (see JSON via_node)');
      emitResult(lines, { url, delay_ms: null, via_node: viaNode, status: null, error: e.message || 'unknown' });
      return 1;
    }
    lines.push('Proxy test ok: HTTP ' + r.status + ' in ' + r.ms + 'ms via port ' + rt.proxy_port);
    emitResult(lines, { url, delay_ms: r.ms, via_node: viaNode, status: r.status });
    return 0;
  }

  // ---- --all：组测速 ----
  lines.push('Group delay test started (' + GROUP_NAME + ', window ' + (GROUP_DELAY_TIMEOUT_MS / 1000) + 's for the whole pool)...');
  const g = await groupDelay(rt.api_port, rt.secret, url);
  if (!g.ok || !g.map) {
    lines.push('Group delay test FAILED: ' + g.reason + ' (' + g.ms + 'ms)');
    emitResult(lines, { url, delay_ms: null, via_node: viaNode, top5: [], responded: 0, tested_ms: g.ms, error: g.reason });
    return 1;
  }
  const entries = Object.entries(g.map).filter(([, v]) => typeof v === 'number');
  entries.sort((a, b) => a[1] - b[1]);
  const top = entries.slice(0, TOP_N);
  const curDelay = viaNode && typeof g.map[viaNode] === 'number' ? g.map[viaNode] : null;
  lines.push('Group delay test done in ' + g.ms + 'ms: ' + entries.length + ' nodes responded');
  lines.push('Top ' + top.length + ' delays: ' + (top.map(([, d]) => d + 'ms').join(', ') || 'n/a') + ' (node names in JSON)');
  if (viaNode) lines.push('Current node delay: ' + (curDelay === null ? 'no answer' : curDelay + 'ms'));
  emitResult(lines, {
    url, delay_ms: curDelay, via_node: viaNode,
    top5: top.map(([name, d]) => ({ name, delay_ms: d })),
    responded: entries.length,
    tested_ms: g.ms,
  });
  return entries.length > 0 ? 0 : 1;
}

module.exports = { handle };
