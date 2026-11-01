/**
 * api.js — mihomo external-controller REST 客户端（设计 §2/§3.4/§4）
 *
 * 端点封装：GET /version、GET /traffic（流式——每秒推送 JSON 行，保险丝数据源）、
 *           GET /connections、DELETE /connections、GET /proxies/:group（POOL）、
 *           GET /proxies（全量，degraded 判定用）、PUT /providers/proxies/:name（热更）。
 *
 * 约束（§3.6/§8）：
 *  - 仅 127.0.0.1（external-controller 只 bind 本机回环，唯一消费者=CLI/watcher）
 *  - Bearer 认证（随机 32hex secret）
 *  - 全部走 node 内置 http（自包含，§8——排除系统 curl）
 *
 * 容错风格：request 失败一律 resolve(null)（与 core.apiRequest 同约定；core 的 t1
 * 遗留内部函数保留不动，本模块为统一客户端，watcher / cmd-update / t4 消费）。
 * t4 批次在本模块追加 cmdTest / cmdDoctor handler（vpn.js 路由已指向本文件）。
 */

'use strict';

const http = require('http');

const HOST = '127.0.0.1'; // 本机回环 only（§3.6）

/**
 * 单次 REST 请求。成功 resolve {status, body}，任何失败 resolve null（容错优先）。
 */
function request(apiPort, secret, method, apiPath, timeoutMs) {
  return new Promise(resolve => {
    const req = http.request({
      host: HOST, port: apiPort, path: apiPath, method,
      timeout: timeoutMs || 3000,
      headers: { Authorization: 'Bearer ' + (secret || '') },
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

/**
 * JSON 请求：resolve {status, json}（body 非 JSON 时 json=null），失败 null。
 */
async function requestJson(apiPort, secret, method, apiPath, timeoutMs) {
  const r = await request(apiPort, secret, method, apiPath, timeoutMs);
  if (!r) return null;
  let json = null;
  try { json = JSON.parse(r.body); } catch (e) { json = null; }
  return { status: r.status, json };
}

// ---------- 端点封装 ----------

/** GET /version → 版本串或 null（就绪探针/存活判定） */
async function getVersion(apiPort, secret) {
  const r = await requestJson(apiPort, secret, 'GET', '/version', 3000);
  return (r && r.status === 200 && r.json && typeof r.json.version === 'string') ? r.json.version : null;
}

/** GET /connections → {activeCount, downloadTotal, uploadTotal} 或 null（保险丝辅助校验） */
async function getConnections(apiPort, secret) {
  const r = await requestJson(apiPort, secret, 'GET', '/connections', 3000);
  if (!r || r.status !== 200 || !r.json) return null;
  const conns = Array.isArray(r.json.connections) ? r.json.connections : [];
  return {
    activeCount: conns.length,
    downloadTotal: typeof r.json.downloadTotal === 'number' ? r.json.downloadTotal : 0,
    uploadTotal: typeof r.json.uploadTotal === 'number' ? r.json.uploadTotal : 0,
  };
}

/** DELETE /connections → bool（优雅停第一步，§3.4；尽力而为） */
async function deleteConnections(apiPort, secret) {
  const r = await request(apiPort, secret, 'DELETE', '/connections', 3000);
  return !!r && (r.status === 200 || r.status === 204);
}

/** GET /proxies → 全量 proxies 对象或 null（degraded 判定：POOL 组逐节点 alive 统计） */
async function getProxies(apiPort, secret) {
  const r = await requestJson(apiPort, secret, 'GET', '/proxies', 4000);
  return (r && r.status === 200 && r.json) ? r.json : null;
}

/**
 * GET /providers/proxies → 全量 provider 节点对象或 null（t7 Top 导出数据源）。
 * 实测（t7）：/proxies 的 proxies map 只含组与内建策略（8 条），provider 节点对象
 * 与 history 延迟只在 /providers/proxies 展开（{providers: {name: {proxies: [...]}}}）。
 */
async function getProviderAll(apiPort, secret) {
  const r = await requestJson(apiPort, secret, 'GET', '/providers/proxies', 8000);
  return (r && r.status === 200 && r.json) ? r.json : null;
}

/** GET /proxies/:group → 组对象或 null（如 /proxies/POOL：now/all 等） */
async function getGroup(apiPort, secret, groupName) {
  const r = await requestJson(apiPort, secret, 'GET', '/proxies/' + encodeURIComponent(groupName), 3000);
  return (r && r.status === 200 && r.json) ? r.json : null;
}

/** PUT /providers/proxies/:name → bool（provider 热更，§3.2；204/200 视为成功） */
async function putProvider(apiPort, secret, providerName) {
  const r = await request(apiPort, secret, 'PUT', '/providers/proxies/' + encodeURIComponent(providerName), 8000);
  return !!r && (r.status === 200 || r.status === 204);
}

// ---------- /traffic 流式订阅（§3.4 保险丝数据源） ----------
//
// mihomo 对 GET /traffic 保持 chunked 流，每秒推送一行 JSON {"up":..,"down":..}（bytes/s）。
// 本函数封装为长订阅：按行解析回调 onSample({up, down, t})；断线自动重连
// （指数退避 1s→30s；watcher 侧无需自管重连）；stop() 后不再重连。
// onEvent(kind) 仅回传枚举事件（'open'/'retry'），供 watcher.log 白名单记录。

function openTrafficStream(opts) {
  const o = opts || {};
  let stopped = false;
  let attempt = 0;
  let current = null;
  let timer = null;

  const fire = kind => { if (typeof o.onEvent === 'function') { try { o.onEvent(kind); } catch (e) { /* 消费异常不反噬 */ } } };

  const open = () => {
    if (stopped) return;
    let settled = false; // 单连接生命周期内 fail 只触发一次（end/error/timeout 多路复用）
    const fail = () => {
      if (settled || stopped) return;
      settled = true;
      fire('retry');
      const delay = Math.min(30000, 1000 * Math.pow(2, attempt++));
      timer = setTimeout(open, delay);
    };
    current = http.request({
      host: HOST, port: o.port, path: '/traffic', method: 'GET',
      headers: { Authorization: 'Bearer ' + (o.secret || '') },
      timeout: 15000, // socket idle 超时：正常每秒有样本，15s 无数据视为挂死
    }, res => {
      if (res.statusCode !== 200) { res.resume(); fail(); return; }
      attempt = 0; // 成功建立即重置退避
      fire('open');
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', chunk => {
        buf += chunk;
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (!line) continue;
          let j = null;
          try { j = JSON.parse(line); } catch (e) { j = null; }
          if (j && typeof j.up === 'number' && typeof j.down === 'number' && typeof o.onSample === 'function') {
            try { o.onSample({ up: j.up, down: j.down, t: Date.now() }); } catch (e) { /* 同上 */ }
          }
        }
      });
      res.on('end', fail);   // 服务端关闭（内核退出等）→ 重连
      res.on('error', fail);
    });
    current.on('timeout', () => { try { current.destroy(); } catch (e) { /* 已断 */ } fail(); });
    current.on('error', fail);
    current.end();
  };

  open();

  return {
    stop() {
      stopped = true;
      if (timer) { clearTimeout(timer); timer = null; }
      if (current) { try { current.destroy(); } catch (e) { /* 已断 */ } }
    },
  };
}

module.exports = {
  request,
  requestJson,
  getVersion,
  getConnections,
  deleteConnections,
  getProxies,
  getProviderAll,
  getGroup,
  putProvider,
  openTrafficStream,
};
