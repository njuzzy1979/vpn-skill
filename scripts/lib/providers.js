/**
 * providers.js — 免费源多通道拉取 + 校验 + 原子写缓存
 *
 * 职责（设计 §3.2 / §2 数据流步骤①）：
 *  - 读 user/sources.yaml 免费源清单（三通道并列）
 *    - t5：条目可带 format: uri（URI 行列表/整体 base64 源，r2 §1/§2）——
 *      拉取文本经 lib/uri-parser 解析为 proxies 数组后走同一校验/原子写链；
 *      缺省 format 走 clash yaml 原文直存路径（既有三源零回归）
 *  - 每源按通道序拉取（上次成功通道优先，读 var/runtime.json.last_channel；
 *    runtime 读取为容错直读——t1 的 runtime 接口未就绪，直接读文件，
 *    读不到/损坏均按空处理，联调时由编排器收口）
 *  - node 内置 https 直连拉取（不走系统代理、不走池代理）
 *  - 校验：yaml 可解析 + proxies 数组存在 + 非空 + 节点数 ≤ max_nodes
 *  - 原子写 var/providers/free-<name>.yaml（临时文件 + rename）
 *  - 失败降级：单源全通道失败 → 写空池占位 `proxies: []`，不抛异常（VR2：
 *    内核对空占位的加载行为，内核可用时实测，否则 DEFERRED）
 *
 * R2 红线：失败信息不含 URL 全文（截断 host）；免费源 URL 本身无凭据，
 * 截断为防御性冗余。订阅 URL 绝不经过本模块。
 *
 * 本模块同时导出 t2 域内共享工具（atomicWrite / readYamlFile / readJsonSafe /
 * maskUrl / httpsGet），供 config.js / cmd-setup.js / cmd-update.js 复用；
 * t1 的 util.js 就绪后由编排器联调收口（本文件不触碰 t1 域）。
 */

'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const yaml = require('../vendor/yaml');
const util = require('./util'); // t3 联调收口：runtime 读写协议与脱敏统一走 util（§4.1/§7）
const uriParser = require('./uri-parser'); // t5：URI 型源解析（纯函数，r2 §2）

// ── 路径（基于 __dirname 向上定位 skill 根，禁止绝对路径硬编码） ──
const SKILL_ROOT = path.resolve(__dirname, '..', '..');
const USER_DIR = path.join(SKILL_ROOT, 'user');
const VAR_DIR = path.join(SKILL_ROOT, 'var');
const PROVIDERS_DIR = path.join(VAR_DIR, 'providers');
const SOURCES_FILE = path.join(USER_DIR, 'sources.yaml');
const RUNTIME_FILE = path.join(VAR_DIR, 'runtime.json');

// ── 拉取参数 ──
const FETCH_TIMEOUT_MS = 8000;            // 单通道超时（与设计 §3.1 引导链同量级）
const MAX_BODY_BYTES = 20 * 1024 * 1024;  // 响应体硬上限（size-limit 同思路，防恶意超大源）
const DEFAULT_MAX_NODES = 2000;           // 校验兜底默认值（sources.yaml 可覆盖）
const DEFAULT_CHANNEL_ORDER = ['direct', 'jsdelivr', 'ghproxy'];
const UA = 'vpn-skill/0.1 (node ' + process.version + ')';
const DEGRADED_SKIP_RATE = 0.5;           // t5：URI 源解析跳过率超过此值记 degraded 警告（不阻塞）
const PROVIDERS_LOG = path.join(VAR_DIR, 'logs', 'providers.log');

// ═══════════════ 共享工具（t2 域内导出） ═══════════════

/**
 * 容错读 yaml 文件：不存在 / 解析失败 → null（不抛异常）
 */
function readYamlFile(p) {
  try {
    const raw = fs.readFileSync(p, 'utf8');
    return yaml.parse(raw) || null;
  } catch (_) {
    return null;
  }
}

/**
 * 容错读 json 文件：不存在 / 解析失败 → null（不抛异常）
 */
function readJsonSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (_) {
    return null;
  }
}

/**
 * 原子写：临时文件 + rename（设计 §2 并发安全约定）。
 * Windows 上 rename 覆盖已存在目标可能瞬态 EPERM（AV 扫描/他进程读取竞态），
 * 做短重试；仍失败则退化为 unlink 后 rename。
 */
function atomicWrite(p, content) {
  const tmp = p + '.tmp-' + process.pid + '-' + Date.now();
  fs.writeFileSync(tmp, content, 'utf8');
  let lastErr = null;
  for (let i = 0; i < 3; i++) {
    try {
      fs.renameSync(tmp, p);
      return;
    } catch (e) {
      lastErr = e;
      // 短暂等待后重试（同步阻塞 ~50ms，写配置场景可接受）
      const until = Date.now() + 50;
      while (Date.now() < until) { /* busy wait */ }
    }
  }
  try {
    fs.unlinkSync(p);
    fs.renameSync(tmp, p);
    return;
  } catch (e) {
    lastErr = e;
  }
  try { fs.unlinkSync(tmp); } catch (_) { /* 清理失败忽略 */ }
  throw lastErr;
}

/**
 * R2：URL 截断——失败信息只给协议 + host 前缀，绝不含 URL 全文。
 * 例：https://raw.githubusercontent.com/a/b/c.yml → https://raw.githubuser…
 */
function maskUrl(u) {
  try {
    const parsed = new URL(u);
    const host = parsed.hostname || '';
    const short = host.length > 16 ? host.slice(0, 16) : host;
    return `${parsed.protocol}//${short}…`;
  } catch (_) {
    return '<invalid-url>';
  }
}

/**
 * node 内置 https GET（直连，不走任何代理）。
 * 支持 ≤3 次重定向跟随、总大小上限、socket idle 超时。
 * 返回 { status, body: Buffer, ms }（ms 含重定向全程）。
 */
function httpsGet(urlStr, opts) {
  const o = opts || {};
  const timeoutMs = o.timeoutMs || FETCH_TIMEOUT_MS;
  const maxBytes = o.maxBytes || MAX_BODY_BYTES;
  const maxRedirects = o.maxRedirects === undefined ? 3 : o.maxRedirects;
  const started = o._started || Date.now();
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      return reject(new Error('invalid url'));
    }
    if (u.protocol !== 'https:') return reject(new Error('https only'));
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: 'GET',
        headers: { 'User-Agent': UA, Accept: '*/*' },
        timeout: timeoutMs,
      },
      (res) => {
        const status = res.statusCode || 0;
        // 重定向跟随
        if (status >= 300 && status < 400 && res.headers.location && maxRedirects > 0) {
          res.resume(); // 丢弃当前响应体
          const next = new URL(res.headers.location, u).toString();
          httpsGet(next, { ...o, maxRedirects: maxRedirects - 1, _started: started })
            .then(resolve, reject);
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > maxBytes) {
            req.destroy(new Error('body exceeds ' + maxBytes + ' bytes'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve({ status, body: Buffer.concat(chunks), ms: Date.now() - started }));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout after ' + timeoutMs + 'ms')));
    req.on('error', reject);
    req.end();
  });
}

// ═══════════════ 免费源拉取主逻辑 ═══════════════

/**
 * 通道尝试序：上次成功通道优先，其余按默认序（direct → jsdelivr → ghproxy），
 * 未识别的通道键附加在末尾（sources.yaml 用户可扩展）。
 */
function channelOrder(channels, preferred) {
  const keys = Object.keys(channels || {});
  const base = DEFAULT_CHANNEL_ORDER
    .filter((k) => channels && channels[k])
    .concat(keys.filter((k) => !DEFAULT_CHANNEL_ORDER.includes(k)));
  if (preferred && channels && channels[preferred] && base[0] !== preferred) {
    return [preferred].concat(base.filter((k) => k !== preferred));
  }
  return base;
}

/**
 * 校验响应体：yaml 可解析 + proxies 为数组 + 非空 + 节点数 ≤ maxNodes。
 * 返回 { ok: true, nodes } 或 { ok: false, reason }（reason 不含 URL/凭据）。
 */
function validateProxiesBody(bodyBuf, maxNodes) {
  let doc;
  try {
    doc = yaml.parse(bodyBuf.toString('utf8'));
  } catch (_) {
    return { ok: false, reason: 'yaml parse failed' };
  }
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.proxies)) {
    return { ok: false, reason: 'proxies array missing' };
  }
  const n = doc.proxies.length;
  if (n === 0) return { ok: false, reason: 'proxies empty' };
  if (maxNodes && n > maxNodes) return { ok: false, reason: 'node count ' + n + ' exceeds max ' + maxNodes };
  return { ok: true, nodes: n };
}

/**
 * t5：URI 源 degraded 警告——跳过率 > DEGRADED_SKIP_RATE 时落盘 var/logs/providers.log。
 * 行风格仿 watcher.wlog（时间戳 + level + event + k=v 字段）；字段只含计数值与
 * 枚举原因码（解析层已保证零凭据），再过 util.sanitize 作防御性冗余（R2）。
 */
function logDegraded(name, channel, stats) {
  try {
    fs.mkdirSync(path.join(VAR_DIR, 'logs'), { recursive: true });
  } catch (_) { /* 目录已存在或创建失败都不影响主流程 */ }
  util.appendLogLine(
    PROVIDERS_LOG,
    util.sanitize(
      [
        new Date().toISOString(),
        'warn',
        'event=uri-source-degraded',
        'source=' + name,
        'channel=' + channel,
        'container=' + stats.container,
        'candidates=' + stats.candidates,
        'parsed=' + stats.parsed,
        'skipped=' + stats.skipped,
        'skip_rate=' + stats.skipRate.toFixed(2),
        'reasons=' + JSON.stringify(stats.reasons),
      ].join(' ')
    )
  );
}

/**
 * 拉取单个免费源：逐通道尝试至首个成功；成功则原文原子写缓存
 * （保留上游原文，mihomo file provider 自行解析）；全通道失败写空池占位。
 * 绝不抛异常（失败降级是设计行为，VR2）。
 *
 * t5 扩展：source.format === 'uri' 时，拉取文本 → uri-parser 逐行解析 → 过滤
 * 非法 → proxies 数组 → 序列化为 yaml 落同一缓存链（校验语义与 yaml 源同构：
 * 空池拒收 / 超max_nodes拒收 / 原子写 / 全通道失败空占位）。缺省 format 走
 * 原 yaml 路径（既有三源零回归）。
 */
async function refreshOne(source, preferredChannel) {
  const name = source.name;
  const isUri = source.format === 'uri';
  const maxNodes = Number(source.max_nodes) > 0 ? Number(source.max_nodes) : DEFAULT_MAX_NODES;
  const channels = source.channels || {};
  const order = channelOrder(channels, preferredChannel);
  const attempts = [];
  // t3 收口点（maskUrl→sanitize 升级）：失败明细 = maskUrl 截断 host + 经 util.sanitize
  // 统一脱敏兜底（用户自定义源通道 URL 若带凭据形态，两层都不放过；R2 对齐）
  const failInfo = (url, msg) =>
    util.sanitize(maskUrl(url) + ' ' + (msg || 'fetch failed'));
  for (const ch of order) {
    const url = channels[ch];
    try {
      const { body, ms } = await httpsGet(url);

      if (isUri) {
        // ── t5 URI 路径：解析 → 同构校验 → 序列化落缓存 ──
        const parsed = uriParser.parseSubscriptionText(body.toString('utf8'));
        const n = parsed.proxies.length;
        if (n === 0) {
          attempts.push({ channel: ch, error: failInfo(url, 'no valid nodes (candidates ' + parsed.stats.candidates + ', skipped ' + parsed.stats.skipped + ')') });
          continue;
        }
        if (maxNodes && n > maxNodes) {
          attempts.push({ channel: ch, error: failInfo(url, 'node count ' + n + ' exceeds max ' + maxNodes) });
          continue;
        }
        // 文件头注释只含源名/计数值（R2：凭据仅存在于 proxies 节内，缓存目录已 gitignore）
        const out = '# generated from uri source ' + name + ' at ' + new Date().toISOString() +
          ' | container=' + parsed.stats.container + ' candidates=' + parsed.stats.candidates +
          ' parsed=' + n + ' skipped=' + parsed.stats.skipped + '\n' +
          yaml.stringify({ proxies: parsed.proxies }) + '\n';
        atomicWrite(path.join(PROVIDERS_DIR, 'free-' + name + '.yaml'), out);
        const res = {
          name, ok: true, channel: ch, nodes: n, ms, attempts,
          container: parsed.stats.container,
          skipped: parsed.stats.skipped,
          candidateLines: parsed.stats.candidates,
        };
        if (parsed.stats.skipRate > DEGRADED_SKIP_RATE) {
          res.degraded = true;
          res.skip_rate = Math.round(parsed.stats.skipRate * 100) / 100;
          logDegraded(name, ch, parsed.stats); // 警告不阻塞（设计：脏数据是免费源常态）
        }
        return res;
      }

      // ── 既有 yaml 路径（零回归） ──
      const v = validateProxiesBody(body, maxNodes);
      if (!v.ok) {
        attempts.push({ channel: ch, error: failInfo(url, v.reason) });
        continue;
      }
      atomicWrite(path.join(PROVIDERS_DIR, 'free-' + name + '.yaml'), body);
      return { name, ok: true, channel: ch, nodes: v.nodes, ms, attempts };
    } catch (e) {
      attempts.push({ channel: ch, error: failInfo(url, e && e.message ? e.message : 'fetch failed') });
    }
  }
  // 全通道失败 → 空池占位（设计 §2 步骤①降级路径，不阻塞启动）
  atomicWrite(path.join(PROVIDERS_DIR, 'free-' + name + '.yaml'), 'proxies: []\n');
  return { name, ok: false, channel: null, nodes: 0, ms: 0, attempts };
}

/**
 * 刷新全部免费源（update 子命令与 watcher 刷新调度共用入口）。
 *
 * @returns {Promise<{results: Array, okCount: number, failCount: number}>}
 *   results[]: { name, ok, channel, nodes, ms, attempts[] }
 * @throws sources.yaml 缺失/为空时抛错（skill 安装损坏，非运行时降级场景）
 */
async function refreshAll() {
  const srcDoc = readYamlFile(SOURCES_FILE);
  if (!srcDoc || !Array.isArray(srcDoc.sources) || srcDoc.sources.length === 0) {
    throw new Error('sources.yaml missing or empty (skill install broken)');
  }
  fs.mkdirSync(PROVIDERS_DIR, { recursive: true });

  // runtime.json 读取——t3 联调收口点：util.readRuntime 替换容错直读（缺失/损坏按 {}）
  const rt = util.readRuntime(SKILL_ROOT);
  const lastChannel = (rt.last_channel && typeof rt.last_channel === 'object') ? rt.last_channel : {};

  // 三源并行拉取（各自独立通道序，互不阻塞）
  const results = await Promise.all(
    srcDoc.sources.map((s) => refreshOne(s, lastChannel[s.name]))
  );

  // 拉取完成后单次回写——t3 联调收口点：util.writeRuntimeAtomic 写协议（§4.1）替换
  // 全量覆盖写：读快照→仅改本写者字段（last_channel/last_refresh）→write_seq 条件写，
  // 与 watcher 心跳/CLI start 并发时不再丢失他写者字段（t3 测试点 7 的修复本体）
  const okResults = results.filter((r) => r.ok);
  if (okResults.length > 0) {
    const stamp = new Date().toISOString();
    const ok = util.writeRuntimeAtomic(SKILL_ROOT, (s) => {
      const baseCh = (s.last_channel && typeof s.last_channel === 'object') ? s.last_channel : {};
      const baseRf = (s.last_refresh && typeof s.last_refresh === 'object') ? s.last_refresh : {};
      const newCh = Object.assign({}, baseCh);
      const newRf = Object.assign({}, baseRf);
      for (const r of okResults) {
        newCh[r.name] = r.channel;
        newRf[r.name] = stamp;
      }
      s.last_channel = newCh;
      s.last_refresh = newRf;
    });
    if (!ok) {
      // runtime 写失败不使刷新失败（写协议 3 次重试后放弃；下一轮刷新/心跳自愈）
    }
  }

  const okCount = okResults.length;
  return { results, okCount, failCount: results.length - okCount };
}

module.exports = {
  refreshAll,
  // 域内共享工具
  readYamlFile,
  readJsonSafe,
  atomicWrite,
  maskUrl,
  httpsGet,
  // 路径常量（cmd 层消费）
  paths: {
    skillRoot: SKILL_ROOT,
    userDir: USER_DIR,
    varDir: VAR_DIR,
    providersDir: PROVIDERS_DIR,
    sourcesFile: SOURCES_FILE,
    runtimeFile: RUNTIME_FILE,
  },
};
