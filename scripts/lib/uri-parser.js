/**
 * uri-parser.js — 四协议 URI → mihomo proxies 对象（t5，设计 §10 / r2 §2）
 *
 * 职责：纯函数解析，不发任何网络请求。
 *  - vmess://  base64(JSON) 主格式（r2 §2.1 生态主流）；userinfo 形态（v2ray
 *    Planning#39，非目标#6 留点）尽力解析，失败跳过
 *  - vless://  query 参数 → tls/reality/传输层字段映射
 *  - trojan:// password@host:port + query（peer 为 SNI 兜底，r2 §2.1）
 *  - ss://     SIP002 base64 userinfo / 2022 明文 userinfo / legacy 整体 base64
 *              三形态，cipher 白名单过滤（防生成 mihomo 拒载的 provider 文件）
 *  - 容器两种（r2 §2.1 实测修正）：明文 URI 行列表 / 整体 base64（先试解码再按行拆）
 *
 * 脏行跳过不阻塞整源：每行独立 try，失败按枚举原因码计数（parseSubscriptionText
 * 返回 stats）；原因码与计数均不含 URI 原文/凭据（R2：解析错误信息零凭据）。
 * 节点名唯一化（#2/#3 后缀）：防同名节点导致 provider 文件整体拒载。
 * 输出为裸 proxies（[free:源名] 前缀由 mihomo provider override 层统一加，设计 §3.2）。
 */

'use strict';

// ── mihomo 支持的 ss cipher 白名单（r2 §2.2：官方 40+ 种；此处收录实测生态
//    常用集 + 2022 系。白名单外的 method 直接跳过该行——比生成内核拒载的
//    配置更安全，脏数据是免费源常态） ──
const SS_CIPHERS = new Set([
  // AEAD
  'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
  'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
  // 2022 系（SIP002 明文 userinfo 形态的典型主力）
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
  'none',
  // 常见流加密（免费源遗留形态）
  'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
  'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
  'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb',
  'rc4-md5', 'chacha20', 'chacha20-ietf', 'xchacha20',
  'cast5-cfb', 'bf-cfb',
  'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
]);

// mihomo vmess cipher（scy 缺省 auto；白名单外归一为 auto——服务端按 UUID
// 识别客户端加密，scy 异常值多为主流 auto 的别名/脏值，归一比拒载安全）
const VMESS_CIPHERS = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero']);

// mihomo 四协议支持的传输层（vmess net / vless+trojan type 参数）
const TRANSPORTS = new Set(['ws', 'grpc', 'h2']);

// ═══════════════ 基础工具（纯函数） ═══════════════

/**
 * 宽容 base64 解码：去空白、URL-safe 变体归一（-→+ _→/）、补 padding。
 * 字符集校验严格（防把任意文本当 base64 误解码）。失败返回 null。
 * 注：不限制可打印性——vmess JSON 的 ps 字段常态为中文/emoji（r2 §1 实调），
 * 可打印约束仅用于 userinfo/凭据域（b64decodeAscii）。
 */
function b64decode(s) {
  const clean = String(s).replace(/\s+/g, '');
  if (!clean || clean.length < 2) return null;
  // 同时接受标准 base64（+/）与 URL-safe 变体（-_）；归一在下一步完成
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(clean)) return null;
  const norm = clean.replace(/-/g, '+').replace(/_/g, '/');
  const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4);
  try {
    const out = Buffer.from(padded, 'base64').toString('utf8');
    return out || null;
  } catch (_) {
    return null;
  }
}

/** 凭据/userinfo 域解码：在 b64decode 上加可打印 ASCII 约束（方法/密码域）。 */
function b64decodeAscii(s) {
  const out = b64decode(s);
  if (out === null || !/^[\x20-\x7e]*$/.test(out)) return null;
  return out;
}

/** percent 解码（失败回原文，不抛） */
function pctDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch (_) {
    return s;
  }
}

/**
 * 大小写不敏感取 query 参数（URLSearchParams 键大小写敏感，而免费源参数
 * 大小写混乱：allowInsecure/allowinsecure、serviceName/servicename 混用常态）
 */
function paramGet(params, name) {
  const direct = params.get(name); // 精确命中优先（多数源参数本就规范）
  if (direct !== null) return direct;
  const target = name.toLowerCase();
  for (const [k, v] of params) {
    if (k.toLowerCase() === target) return v;
  }
  return null;
}

/** 主机名校验：域名 / IPv4 / [IPv6] / 裸 IPv6 / localhost（宽松白名单） */
function validHost(h) {
  if (typeof h !== 'string') return false;
  const host = h.trim().toLowerCase();
  if (!host || host.length > 253) return false;
  if (/^\[?[0-9a-f:]+\]?$/.test(host)) return host.includes(':'); // IPv6
  if (host === 'localhost') return true;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host);
}

/** 端口校验：1-65535 整数（URL.port 为字符串，vmess JSON 可能是数字） */
function validPort(p) {
  const n = Number(p);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/**
 * 去除对象中 undefined / null / '' / 空对象 值的键——mihomo 对空值字段
 * 拒载风险不明，只写有意义的字段（防御纵深）。
 */
function compact(obj) {
  const out = {};
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === undefined || v === null || v === '') continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    out[k] = v;
  }
  return out;
}

/** URL userinfo 的传输层参数 → mihomo network/-opts 映射（vless/trojan 共用） */
function transportFromParams(type, params) {
  const t = (type || 'tcp').toLowerCase();
  if (t === 'tcp' || t === '' || t === 'none' || t === 'raw') return {};
  if (!TRANSPORTS.has(t)) return null; // kcp/quic/domainsocket 等不支持 → 调用方跳过
  if (t === 'ws') {
    return compact({
      network: 'ws',
      'ws-opts': compact({
        path: paramGet(params, 'path') || '/',
        headers: paramGet(params, 'host') ? { Host: paramGet(params, 'host') } : null,
      }),
    });
  }
  if (t === 'grpc') {
    return {
      network: 'grpc',
      'grpc-opts': { 'grpc-service-name': paramGet(params, 'servicename') || paramGet(params, 'serviceName') || paramGet(params, 'path') || '' },
    };
  }
  // h2
  const host = paramGet(params, 'host');
  return compact({
    network: 'h2',
    'h2-opts': compact({ path: paramGet(params, 'path'), host: host ? [host] : null }),
  });
}

/** tls/reality 公共参数（vless/trojan 共用；security 决定形态） */
function tlsFromParams(params) {
  const security = (paramGet(params, 'security') || '').toLowerCase();
  const sni = paramGet(params, 'sni') || paramGet(params, 'peer') || ''; // peer 为 SNI 兜底（r2 §2.1）
  const fp = paramGet(params, 'fp');
  const alpn = paramGet(params, 'alpn');
  const alpnArr = alpn ? alpn.split(',').map((x) => x.trim()).filter(Boolean) : null;
  const insecure = /^(1|true)$/i.test(paramGet(params, 'allowinsecure') || paramGet(params, 'insecure') || '');
  if (security === 'reality') {
    const pbk = paramGet(params, 'pbk');
    if (!pbk) return null; // reality 无公钥 → 无效节点
    return compact({
      tls: true,
      servername: sni || undefined,
      'client-fingerprint': fp || undefined,
      alpn: alpnArr || undefined,
      'skip-cert-verify': insecure || undefined,
      'reality-opts': compact({ 'public-key': pbk, 'short-id': paramGet(params, 'sid') }),
    });
  }
  if (security === 'tls' || security === 'xtls') {
    return compact({
      tls: true,
      servername: sni || undefined,
      'client-fingerprint': fp || undefined,
      alpn: alpnArr || undefined,
      'skip-cert-verify': insecure || undefined,
    });
  }
  // security=none/缺省：trojan 本身恒 TLS（协议内生），不写字段由内核默认处理
  return compact({
    servername: sni || undefined,
    'client-fingerprint': fp || undefined,
    alpn: alpnArr || undefined,
    'skip-cert-verify': insecure || undefined,
  });
}

// ═══════════════ 四协议解析器（每条独立 try 由调用方保证） ═══════════════

/**
 * vmess base64(JSON) 主格式 → mihomo vmess proxy。
 * 字段映射（r2 §2.1 JSON → r2 §2.2 mihomo）：
 * ps→name add→server port→port id→uuid aid→alterId scy→cipher
 * net→network(+ws/h2/grpc-opts) tls→tls sni→servername host→ws Host
 * path→ws/h2 path fp→client-fingerprint alpn→alpn
 */
function vmessFromJson(j, fallbackName) {
  if (!j || typeof j !== 'object') return null;
  const server = typeof j.add === 'string' ? j.add.trim() : '';
  const port = validPort(j.port);
  const uuid = typeof j.id === 'string' ? j.id.trim() : '';
  if (!server || !port || !uuid || !validHost(server)) return null;
  const net = (typeof j.net === 'string' && j.net.trim()) ? j.net.trim().toLowerCase() : 'tcp';
  const scy = typeof j.scy === 'string' ? j.scy.trim().toLowerCase() : '';
  const name = (typeof j.ps === 'string' && j.ps.trim()) ? j.ps.trim() : (fallbackName || '');

  const proxy = { name, type: 'vmess', server, port, uuid };
  proxy.alterId = Number(j.aid) || 0;
  proxy.cipher = VMESS_CIPHERS.has(scy) ? scy : 'auto';

  // 传输层：tcp(http 伪装)/ws/h2/grpc/httpupgrade；其余（kcp/quic）不支持
  if (net === 'ws') {
    proxy.network = 'ws';
    const host = typeof j.host === 'string' ? j.host.split(',')[0].trim() : '';
    proxy['ws-opts'] = compact({ path: typeof j.path === 'string' ? j.path : '/', headers: host ? { Host: host } : null });
  } else if (net === 'h2') {
    proxy.network = 'h2';
    const host = typeof j.host === 'string' ? j.host.trim() : '';
    proxy['h2-opts'] = compact({ path: typeof j.path === 'string' ? j.path : null, host: host ? [host] : null });
  } else if (net === 'grpc') {
    proxy.network = 'grpc';
    proxy['grpc-opts'] = { 'grpc-service-name': typeof j.path === 'string' ? j.path : '' };
  } else if (net === 'http' || (net === 'tcp' && j.type === 'http')) {
    proxy.network = 'http';
  } else if (net === 'httpupgrade') {
    proxy.network = 'httpupgrade';
  } else if (net !== 'tcp' && net !== 'none' && net !== 'raw') {
    return null; // kcp/quic 等未支持传输层 → 跳过
  }

  // tls（vmess JSON 的 tls 字段值为 "tls" 或空）
  if (j.tls === 'tls' || j.tls === true) {
    proxy.tls = true;
    const sni = typeof j.sni === 'string' && j.sni.trim() ? j.sni.trim() : '';
    const host = typeof j.host === 'string' ? j.host.split(',')[0].trim() : '';
    if (sni) proxy.servername = sni;
    else if (host && net === 'ws') proxy.servername = host;
    if (typeof j.fp === 'string' && j.fp.trim()) proxy['client-fingerprint'] = j.fp.trim();
    if (typeof j.alpn === 'string' && j.alpn.trim()) {
      proxy.alpn = j.alpn.split(',').map((x) => x.trim()).filter(Boolean);
    }
  }
  return proxy;
}

/**
 * vmess userinfo 形态（v2ray/Planning#39，非目标#6 边界）：尽力解析，失败 null。
 * 形态：vmess://[base64(uid[:aid])|uid]@host:port?scy/net/tls/path/host/sni=...#name
 */
function vmessFromUserinfo(payload, fallbackName) {
  const at = payload.lastIndexOf('@');
  if (at <= 0) return null;
  const userinfo = payload.slice(0, at);
  const rest = payload.slice(at + 1); // host:port?query
  let uuid = '';
  let aid = 0;
  const dec = b64decodeAscii(userinfo);
  if (dec && dec.includes(':')) {
    const i = dec.indexOf(':');
    uuid = dec.slice(0, i).trim();
    aid = Number(dec.slice(i + 1)) || 0;
  } else if (dec) {
    uuid = dec.trim();
  } else {
    uuid = pctDecode(userinfo).trim(); // 裸 uuid 形态
  }
  if (!uuid) return null;
  let u;
  try {
    u = new URL('vmess://' + rest);
  } catch (_) {
    return null;
  }
  const server = u.hostname.replace(/^\[|\]$/g, '');
  const port = validPort(u.port);
  if (!server || !port || !validHost(server)) return null;
  const p = u.searchParams;
  const scy = (p.get('scy') || '').toLowerCase();
  const net = (p.get('net') || 'tcp').toLowerCase();
  const proxy = { name: fallbackName || '', type: 'vmess', server, port, uuid };
  proxy.alterId = aid || Number(p.get('alterId')) || 0;
  proxy.cipher = VMESS_CIPHERS.has(scy) ? scy : 'auto';
  if (net === 'ws') {
    proxy.network = 'ws';
    proxy['ws-opts'] = compact({ path: p.get('path') || '/', headers: p.get('host') ? { Host: p.get('host') } : null });
  } else if (net === 'grpc') {
    proxy.network = 'grpc';
    proxy['grpc-opts'] = { 'grpc-service-name': p.get('path') || '' };
  } else if (net !== 'tcp' && net !== 'none' && net !== 'raw' && net !== 'h2' && net !== 'http') {
    return null;
  }
  if ((p.get('tls') || '').toLowerCase() === 'tls' || p.get('security') === 'tls') {
    proxy.tls = true;
    const sni = p.get('sni') || p.get('host') || '';
    if (sni) proxy.servername = sni;
  }
  return proxy;
}

/** vless://uuid@host:port?encryption=none&security=...&type=...#name */
function parseVless(uri) {
  let u;
  try {
    u = new URL(uri);
  } catch (_) {
    return null;
  }
  const uuid = pctDecode(u.username).trim();
  const server = u.hostname.replace(/^\[|\]$/g, '');
  const port = validPort(u.port);
  if (!uuid || !server || !port || !validHost(server)) return null;
  const p = u.searchParams;
  const name = pctDecode(u.hash ? u.hash.slice(1) : '').trim();
  const transport = transportFromParams(p.get('type'), p);
  if (transport === null) return null;
  const tls = tlsFromParams(p);
  if (tls === null) return null; // reality 缺 pbk
  return compact(Object.assign(
    { name, type: 'vless', server, port, uuid },
    p.get('flow') ? { flow: p.get('flow') } : null,
    transport,
    tls
  ));
}

/** trojan://password@host:port?sni/peer=...&type=...#name（password 直作 userinfo） */
function parseTrojan(uri) {
  let u;
  try {
    u = new URL(uri);
  } catch (_) {
    return null;
  }
  // userinfo 整体为 password（含 ':' 时两段拼回——trojan 密码可含冒号）
  let password = pctDecode(u.username);
  if (u.password) password += ':' + pctDecode(u.password);
  password = password.trim();
  const server = u.hostname.replace(/^\[|\]$/g, '');
  const port = validPort(u.port);
  if (!password || !server || !port || !validHost(server)) return null;
  const p = u.searchParams;
  const name = pctDecode(u.hash ? u.hash.slice(1) : '').trim();
  const transport = transportFromParams(p.get('type'), p);
  if (transport === null) return null;
  // trojan 的 SNI 字段名是 sni（mihomo trojan 规范），reality 字段与 vless 同构
  const tlsPart = tlsFromParams(p);
  if (tlsPart === null) return null;
  const sni = tlsPart.servername;
  delete tlsPart.servername;
  if (sni) tlsPart.sni = sni;
  return compact(Object.assign(
    { name, type: 'trojan', server, port, password },
    transport,
    tlsPart
  ));
}

/**
 * ss:// 三形态（r2 §2.1）：
 *  SIP002   ss://base64(method:password)@host:port#name
 *  2022     ss://method:password@host:port#name（明文 userinfo，2022 系密码为 b64 key 无 '@'）
 *  legacy   ss://base64(method:password@host:port)#name
 * query 含 plugin（obfs/v2ray-plugin）→ 不支持，跳过（缺 plugin-opts 无法工作）。
 */
function parseSs(uri) {
  let s = uri.slice(5); // 去 ss://
  let name = '';
  const h = s.indexOf('#');
  if (h >= 0) {
    name = pctDecode(s.slice(h + 1)).trim();
    s = s.slice(0, h);
  }
  const q = s.indexOf('?');
  let query = null;
  if (q >= 0) {
    query = new URLSearchParams(s.slice(q + 1));
    s = s.slice(0, q);
  }
  if (query && (query.get('plugin') || query.get('protoparam'))) {
    return { unsupported: 'ss-plugin' };
  }

  let method = '';
  let password = '';
  let hostport = '';
  const at = s.lastIndexOf('@');
  if (at < 0) {
    // legacy 整体 base64
    const dec = b64decodeAscii(s);
    if (!dec) return null;
    const at2 = dec.lastIndexOf('@');
    if (at2 <= 0) return null;
    const cred = dec.slice(0, at2);
    const ci = cred.indexOf(':');
    if (ci <= 0) return null;
    method = cred.slice(0, ci).trim();
    password = cred.slice(ci + 1);
    hostport = dec.slice(at2 + 1);
  } else {
    const userinfo = s.slice(0, at);
    hostport = s.slice(at + 1);
    const dec = b64decodeAscii(userinfo);
    if (dec && dec.includes(':')) {
      // SIP002 base64 userinfo（b64 优先——生态主流）
      const ci = dec.indexOf(':');
      method = dec.slice(0, ci).trim();
      password = dec.slice(ci + 1);
    } else {
      // 2022 明文 userinfo（可能带 percent 编码）
      const plain = pctDecode(userinfo);
      const ci = plain.indexOf(':');
      if (ci <= 0) return null;
      method = plain.slice(0, ci).trim();
      password = plain.slice(ci + 1);
    }
  }
  if (!method || !password) return null;
  if (!SS_CIPHERS.has(method)) return { unsupported: 'ss-cipher:' + method };

  // host:port（尾随 '/' 容错；IPv6 [..]:port）
  hostport = hostport.replace(/\/+$/, '');
  let host = '';
  let portStr = '';
  if (hostport.startsWith('[')) {
    const eb = hostport.indexOf(']');
    if (eb < 0) return null;
    host = hostport.slice(1, eb);
    portStr = hostport.slice(eb + 1).replace(/^:/, '');
  } else {
    const ci = hostport.lastIndexOf(':');
    if (ci <= 0) return null;
    host = hostport.slice(0, ci);
    portStr = hostport.slice(ci + 1);
  }
  const port = validPort(portStr);
  if (!host || !port || !validHost(host)) return null;
  return { name, type: 'ss', server: host, port, cipher: method, password };
}

// ═══════════════ 单行分发与容器处理 ═══════════════

/**
 * 单行解析入口。返回 proxy 对象 / { unsupported: 原因码 } / null（不可解析）。
 * 不抛异常、不含原文的错误信息（R2）。
 */
function parseUriLine(line) {
  const m = line.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  if (scheme === 'vmess') {
    const payload = line.slice(line.indexOf('://') + 3);
    // 冗余 fragment（名字在 JSON ps 内）先剥离——'#' 非 base64 字符会毁解码
    let fbName = '';
    let body = payload;
    const h = payload.indexOf('#');
    if (h >= 0) {
      fbName = pctDecode(payload.slice(h + 1)).trim();
      body = payload.slice(0, h);
    }
    const dec = b64decode(body);
    if (dec) {
      try {
        const j = JSON.parse(dec);
        const proxy = vmessFromJson(j, fbName);
        if (proxy) return proxy;
      } catch (_) { /* JSON 损坏 → 落到 userinfo 尽力路径 */ }
    }
    return vmessFromUserinfo(body, fbName);
  }
  if (scheme === 'vless') return parseVless(line);
  if (scheme === 'trojan') return parseTrojan(line);
  if (scheme === 'ss') return parseSs(line);
  return { unsupported: 'scheme:' + scheme };
}

/** 节点名兜底与唯一化 */
function ensureNames(proxies) {
  const seen = new Map();
  for (const p of proxies) {
    let n = String(p.name || '').replace(/\s+/g, ' ').trim().slice(0, 200);
    if (!n) n = p.type + '-' + p.server + '-' + p.port;
    const cnt = (seen.get(n) || 0) + 1;
    seen.set(n, cnt);
    p.name = cnt === 1 ? n : n + ' #' + cnt;
  }
}

/**
 * 订阅文本 → proxies 数组（容器两格式：明文行列表 / 整体 base64）。
 * @param {string} text 拉取到的原文
 * @returns {{proxies: Array, stats: {candidates: number, parsed: number,
 *            skipped: number, skipRate: number, reasons: Object, container: string}}}
 *   stats 仅含计数值与枚举原因码（R2：零凭据零原文）。
 */
function parseSubscriptionText(text) {
  let body = String(text || '');
  if (body.charCodeAt(0) === 0xfeff) body = body.slice(1); // BOM 容错
  let container = 'plain';
  // 整体 base64 容器：原文无 '://' 时先试解码（r2 §2.1 实测修正的判别法）
  if (!body.includes('://')) {
    const dec = b64decode(body);
    if (dec && dec.includes('://')) {
      body = dec;
      container = 'base64';
    }
  }

  const proxies = [];
  const reasons = {};
  let candidates = 0;
  const bump = (k) => { reasons[k] = (reasons[k] || 0) + 1; };

  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;               // 空行不计候选
    if (line.startsWith('#')) continue; // #profile-title / #subscription-userinfo 注释头
    candidates++;
    let r = null;
    try {
      r = parseUriLine(line);
    } catch (_) {
      r = null; // 单行异常绝不外抛（脏行跳过不阻塞整源）
    }
    if (r && r.unsupported) {
      // 原因码归并：'scheme:hy2'→'scheme'、'ss-cipher:rsa-xxx'→'ss-cipher'、
      // 'ss-plugin' 原样（枚举码 + 非 IPv6/IPv4 的明文 host 片段不属凭据，R2 安全）
      bump(r.unsupported.split(':')[0]);
      continue;
    }
    if (!r) {
      bump('parse-failed');
      continue;
    }
    proxies.push(r);
  }
  ensureNames(proxies);
  const skipped = candidates - proxies.length;
  return {
    proxies,
    stats: {
      candidates,
      parsed: proxies.length,
      skipped,
      skipRate: candidates > 0 ? skipped / candidates : 0,
      reasons,
      container,
    },
  };
}

module.exports = {
  parseSubscriptionText,
  parseUriLine,
  // 白名单导出（测试与诊断用）
  SS_CIPHERS,
};
